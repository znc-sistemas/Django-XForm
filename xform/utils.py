import datetime
import importlib
import json
import logging
import math
import mimetypes
import os
import re
import sys
import uuid

import requests

from urllib.parse import urljoin
from wsgiref.util import FileWrapper
from xml.dom import minidom, Node


from django.conf import settings
from django.core.files.storage import get_storage_class
from django.core.files.uploadedfile import InMemoryUploadedFile
from django.core.validators import ValidationError
from django.db import IntegrityError
from django.http import HttpResponse, Http404
from django.http import HttpResponseNotFound, StreamingHttpResponse
from django.utils import timezone

from rest_framework import exceptions

from .tags import XFORM_ID_STRING, VERSION

PENDING = 0
SUCCESSFUL = 1
FAILED = 2

EXTERNAL_EXPORT_TYPES = ['xls']
EXPORT_EXT = {
    'csv': 'csv',
    'csvzip': 'csv_zip',
    'kml': 'kml',
    'savzip': 'sav_zip',
    'uuid': 'external',
    'xls': 'xls',
    'xlsx': 'xls',
    'zip': 'zip',
}


class XLSFormError(Exception):
    pass


class DuplicateInstance(Exception):
    def __str__(self):
        return 'Duplicate Instance'


class InstanceInvalidUserError(Exception):
    def __str__(self):
        return 'Could not determine the user.'


class InstanceParseError(Exception):
    def __str__(self):
        return 'The instance could not be parsed.'


class InstanceEmptyError(InstanceParseError):
    def __str__(self):
        return 'Empty instance'


class NonUniqueFormIdError(Exception):
    pass


class InstanceMultipleNodeError(Exception):
    pass


class FormIsMergedDatasetError(Exception):
    """Exception class for merged datasets"""

    def __str__(self):
        return 'Submissions are not allowed on merged datasets.'


class FormInactiveError(Exception):
    """Exception class for inactive forms"""

    def __str__(self):
        return 'Form is inactive'


def generate_content_disposition_header(name, extension, show_date=True):
    if name is None:
        return 'attachment;'
    if show_date:
        name = "%s-%s" % (name, timezone.now().strftime("%Y-%m-%d-%H-%M-%S"))
    return 'attachment; filename=%s.%s' % (name, extension)


def _get_all_attributes(node):
    """
    Go through an XML document returning all the attributes we see.
    """
    if hasattr(node, "hasAttributes") and node.hasAttributes():
        for key in node.attributes.keys():
            yield key, node.getAttribute(key)

    for child in node.childNodes:
        for pair in _get_all_attributes(child):
            yield pair


def _flatten_dict_nest_repeats(d, prefix):
    """
    Return a list of XPath, value pairs.

    :param d: A dictionary
    :param prefix: A list of prefixes
    """
    for key, value in d.items():
        new_prefix = prefix + [key]
        if isinstance(value, dict):
            for pair in _flatten_dict_nest_repeats(value, new_prefix):
                yield pair
        elif isinstance(value, list):
            repeats = []

            for i, item in enumerate(value):
                item_prefix = list(new_prefix)  # make a copy
                if isinstance(item, dict):
                    repeat = {}

                    for path, value in _flatten_dict_nest_repeats(
                            item, item_prefix):
                        # TODO: this only considers the first level of repeats
                        repeat.update({u"/".join(path[1:]): value})
                    repeats.append(repeat)
                else:
                    repeats.append({u"/".join(item_prefix[1:]): item})
            yield (new_prefix, repeats)
        else:
            yield (new_prefix, value)


def _gather_parent_node_list(node):
    node_names = []

    # also check for grand-parent node to skip document element
    if node.parentNode and node.parentNode.parentNode:
        node_names.extend(_gather_parent_node_list(node.parentNode))

    node_names.extend([node.nodeName])

    return node_names


def xpath_from_xml_node(node):
    node_names = _gather_parent_node_list(node)

    return "/".join(node_names[1:])


def _xml_node_to_dict(node, repeats=[], encrypted=False):
    if len(node.childNodes) == 0:
        # there's no data for this leaf node
        return None
    elif len(node.childNodes) == 1 and \
            node.childNodes[0].nodeType == node.TEXT_NODE:
        # there is data for this leaf node
        return {node.nodeName: node.childNodes[0].nodeValue}
    else:
        # this is an internal node
        value = {}

        for child in node.childNodes:
            # handle CDATA text section
            if child.nodeType == child.CDATA_SECTION_NODE:
                return {child.parentNode.nodeName: child.nodeValue}

            d = _xml_node_to_dict(child, repeats)

            if d is None:
                continue

            child_name = child.nodeName
            child_xpath = xpath_from_xml_node(child)
            if list(d) != [child_name]:
                raise AssertionError()
            node_type = dict
            # check if name is in list of repeats and make it a list if so
            # All the photo attachments in an encrypted form use name media
            if child_xpath in repeats or (encrypted and child_name == 'media'):
                node_type = list

            if node_type == dict:
                if child_name not in value:
                    value[child_name] = d[child_name]
                else:
                    # node is repeated, aggregate node values
                    node_value = value[child_name]
                    # 1. check if the node values is a list
                    if not isinstance(node_value, list):
                        # if not a list create
                        value[child_name] = [node_value]
                    # 2. parse the node
                    d = _xml_node_to_dict(child, repeats)
                    # 3. aggregate
                    value[child_name].append(d[child_name])
            else:
                if child_name not in value:
                    value[child_name] = [d[child_name]]
                else:
                    value[child_name].append(d[child_name])
        if value == {}:
            return None
        else:
            return {node.nodeName: value}


def set_uuid(obj):
    """
    Only give an object a new UUID if it does not have one.
    """
    if not obj.uuid:
        obj.uuid = uuid.uuid4().hex


def clean_and_parse_xml(xml_string):
    clean_xml_str = xml_string.strip()
    try:
        clean_xml_str = clean_xml_str.decode("utf-8")
    except Exception:
        pass
    clean_xml_str = re.sub(r">\s+<", u"><", clean_xml_str)
    xml_obj = minidom.parseString(clean_xml_str)
    return xml_obj


def get_meta_from_xml(xml_str, meta_name):
    xml = clean_and_parse_xml(xml_str)
    children = xml.childNodes
    # children ideally contains a single element
    # that is the parent of all survey elements
    if children.length == 0:
        raise ValueError("XML string must have a survey element.")
    survey_node = children[0]
    meta_tags = [n for n in survey_node.childNodes if
                 n.nodeType == Node.ELEMENT_NODE and
                 (n.tagName.lower() == "meta" or
                     n.tagName.lower() == "orx:meta")]
    if len(meta_tags) == 0:
        return None

    # get the requested tag
    meta_tag = meta_tags[0]
    uuid_tags = [n for n in meta_tag.childNodes if
                 n.nodeType == Node.ELEMENT_NODE and
                 (n.tagName.lower() == meta_name.lower() or
                  n.tagName.lower() == u'orx:%s' % meta_name.lower())]
    if len(uuid_tags) == 0:
        return None

    uuid_tag = uuid_tags[0]
    return uuid_tag.firstChild.nodeValue.strip() if uuid_tag.firstChild\
        else None


def flatten(l):
    return [item for sublist in l for item in sublist]


def _get_fields_of_type(xform, types):
    k = []
    survey_elements = flatten(
        [xform.get_survey_elements_of_type(t) for t in types])

    for element in survey_elements:
        name = element.get_abbreviated_xpath()
        k.append(name)

    return k


def get_numeric_fields(xform):
    """List of numeric field names for specified xform"""
    return _get_fields_of_type(xform, ['decimal', 'integer'])


def get_uuid_from_xml(xml):
    def _uuid_only(uuid, regex):
        matches = regex.match(uuid)
        if matches and len(matches.groups()) > 0:
            return matches.groups()[0]
        return None
    uuid = get_meta_from_xml(xml, "instanceID")
    regex = re.compile(r"uuid:(.*)")
    if uuid:
        return _uuid_only(uuid, regex)
    # check in survey_node attributes
    xml = clean_and_parse_xml(xml)
    children = xml.childNodes
    # children ideally contains a single element
    # that is the parent of all survey elements
    if children.length == 0:
        raise ValueError("XML string must have a survey element.")
    survey_node = children[0]
    uuid = survey_node.getAttribute('instanceID')
    if uuid != '':
        return _uuid_only(uuid, regex)
    return None


def numeric_checker(string_value):
    if string_value.isdigit():
        return int(string_value)
    else:
        try:
            value = float(string_value)
            if math.isnan(value):
                value = 0
            return value
        except ValueError:
            pass


def get_values_matching_key(doc, key):
    """
    Returns iterator of values in 'doc' with the matching 'key'.
    """
    def _get_values(doc, key):
        if doc is not None:
            if key in doc:
                yield doc[key]

            for z in doc.items():
                v = z[1]
                if isinstance(v, dict):
                    for item in _get_values(v, key):
                        yield item
                elif isinstance(v, list):
                    for i in v:
                        for j in _get_values(i, key):
                            yield j

    return _get_values(doc, key)


class XFormInstanceParser(object):

    def __init__(self, xml_str, data_dictionary):
        self.dd = data_dictionary
        self.parse(xml_str)

    def parse(self, xml_str):
        self._xml_obj = clean_and_parse_xml(xml_str)
        self._root_node = self._xml_obj.documentElement
        repeats = [e.get_abbreviated_xpath()
                   for e in self.dd.get_survey_elements_of_type(u"repeat")]

        self._dict = _xml_node_to_dict(self._root_node, repeats)
        self._flat_dict = {}

        if self._dict is None:
            raise InstanceEmptyError

        for path, value in _flatten_dict_nest_repeats(self._dict, []):
            self._flat_dict[u"/".join(path[1:])] = value
        self._set_attributes()

    def get_root_node(self):
        return self._root_node

    def get_root_node_name(self):
        return self._root_node.nodeName

    def get(self, abbreviated_xpath):
        return self.to_flat_dict()[abbreviated_xpath]

    def to_dict(self):
        return self._dict

    def to_flat_dict(self):
        return self._flat_dict

    def get_attributes(self):
        return self._attributes

    def _set_attributes(self):
        self._attributes = {}
        all_attributes = list(_get_all_attributes(self._root_node))
        for key, value in all_attributes:
            # Since enketo forms may have the template attribute in
            # multiple xml tags, overriding and log when this occurs
            if key in self._attributes:
                logger = logging.getLogger("console_logger")
                logger.debug("Skipping duplicate attribute: %s"
                             " with value %s" % (key, value))
                logger.debug(str(all_attributes))
            else:
                self._attributes[key] = value

    def get_xform_id_string(self):
        return self._attributes[u"id"]

    def get_version(self):
        return self._attributes.get(u"version")

    def get_flat_dict_with_attributes(self):
        result = self.to_flat_dict().copy()
        result[XFORM_ID_STRING] = self.get_xform_id_string()

        version = self.get_version()
        if version:
            result[VERSION] = self.get_version()

        return result


def response_with_mimetype_and_name(mimetype,
                                    name,
                                    extension=None,
                                    show_date=True,
                                    file_path=None,
                                    use_local_filesystem=False,
                                    full_mime=False):
    if extension is None:
        extension = mimetype
    if not full_mime:
        mimetype = "application/%s" % mimetype
    if file_path:
        try:
            if isinstance(file_path, InMemoryUploadedFile):
                response = StreamingHttpResponse(
                    file_path, content_type=mimetype)
                response['Content-Length'] = file_path.size
            elif not use_local_filesystem:
                default_storage = get_storage_class()()
                wrapper = FileWrapper(default_storage.open(file_path))
                response = StreamingHttpResponse(
                    wrapper, content_type=mimetype)
                response['Content-Length'] = default_storage.size(file_path)
            else:
                wrapper = FileWrapper(open(file_path))
                response = StreamingHttpResponse(
                    wrapper, content_type=mimetype)
                response['Content-Length'] = os.path.getsize(file_path)
        except IOError:
            response = HttpResponseNotFound(
                "The requested file could not be found.")
    else:
        response = HttpResponse(content_type=mimetype)
    response['Content-Disposition'] = generate_content_disposition_header(
        name, extension, show_date)
    return response


def _get_export_type(export_type):
    if export_type in list(EXPORT_EXT):
        export_type = EXPORT_EXT[export_type]
    else:
        raise exceptions.ParseError(
            "'%(export_type)s' format not known or not implemented!" %
            {'export_type': export_type})

    return export_type


def get_file_extension(content_type):
    return mimetypes.guess_extension(content_type)[1:]


def get_media_file_response(metadata, username=None):
    """
    Returns a HTTP response for media files.

    HttpResponse 200 if it represents a file on disk.
    HttpResponseRedirect 302 incase the metadata represents a url.
    HttpResponseNotFound 404 if the metadata file cannot be found.
    """

    if metadata.data_type == 'media' and metadata.data_file:
        file_path = metadata.data_file.name
        filename, extension = os.path.splitext(file_path.split('/')[-1])
        extension = extension.strip('.')
        dfs = get_storage_class()()
        if dfs.exists(file_path):
            return response_with_mimetype_and_name(
                metadata.data_file_type,
                filename,
                extension=extension,
                show_date=False,
                file_path=file_path,
                full_mime=True)
    elif metadata.data_type == 'url' and not metadata.data_file:
        url = requests.Request(
            'GET', metadata.data_value, params={
                'username': username
            }
        ).prepare().url

        try:
            data_file = metadata.get_file(url)
        except Exception:
            raise Http404
        return response_with_mimetype_and_name(
            mimetype=data_file.content_type,
            name=data_file.name,
            extension=get_file_extension(data_file.content_type),
            show_date=False,
            file_path=data_file,
            use_local_filesystem=False,
            full_mime=True
        )
    return HttpResponseNotFound()


def report_exception(*args, **kwargs):
    # dummy
    return


def publish_form(callback):
    """
    Calls the callback function to publish a XLSForm and returns appropriate
    message depending on exception throw during publishing of a XLSForm.
    """
    try:
        return callback()
    # except (PyXFormError, XLSFormError) as e:
    #     return {'type': 'alert-error', 'text': str(e)}
    except IntegrityError as e:
        return {
            'type': 'alert-error',
            'text': 'Form with this id or SMS-keyword already exists.',
        }
    # except ProcessTimedOut as e:
    #     # catch timeout errors
    #     return {
    #         'type': 'alert-error',
    #         'text': 'Form validation timeout, please try again.',
    #     }
    except (MemoryError, OSError) as e:
        return {
            'type': 'alert-error',
            'text': (
                'An error occurred while publishing the form. '
                'Please try again.'
            ),
        }
    except (AttributeError, Exception, ValidationError) as e:
        report_exception("Form publishing exception: {}".format(e), str(e),
                         sys.exc_info())
        return {'type': 'alert-error', 'text': str(e)}


def _get_tag_or_element_type_xpath(xform, tag):
    elems = xform.get_survey_elements_of_type(tag)

    return elems[0].get_abbreviated_xpath() if elems else tag


def calculate_duration(start_time, end_time):
    """
    This function calculates duration when given start and end times.
    An empty string is returned if either of the time formats does
    not match '_format' format else, the duration is returned
    """
    _format = "%Y-%m-%dT%H:%M:%S"
    try:
        _start = datetime.datetime.strptime(start_time[:19], _format)
        _end = datetime.datetime.strptime(end_time[:19], _format)
    except (TypeError, ValueError):
        return ''

    duration = (_end - _start).total_seconds()

    return duration


def inject_instanceid(xml_str, uuid):
    if get_uuid_from_xml(xml_str) is None:
        xml = clean_and_parse_xml(xml_str)
        children = xml.childNodes
        if children.length == 0:
            raise ValueError("XML string must have a survey element.")

        # check if we have a meta tag
        survey_node = children.item(0)
        meta_tags = [
            n for n in survey_node.childNodes
            if n.nodeType == Node.ELEMENT_NODE and n.tagName.lower() == "meta"
        ]
        if len(meta_tags) == 0:
            meta_tag = xml.createElement("meta")
            xml.documentElement.appendChild(meta_tag)
        else:
            meta_tag = meta_tags[0]

        # check if we have an instanceID tag
        uuid_tags = [
            n for n in meta_tag.childNodes
            if n.nodeType == Node.ELEMENT_NODE and n.tagName == "instanceID"
        ]
        if len(uuid_tags) == 0:
            uuid_tag = xml.createElement("instanceID")
            meta_tag.appendChild(uuid_tag)
        else:
            uuid_tag = uuid_tags[0]
        # insert meta and instanceID
        text_node = xml.createTextNode(u"uuid:%s" % uuid)
        uuid_tag.appendChild(text_node)
        return xml.toxml()
    return xml_str


class EnketoError(Exception):

    default_message = "There was a problem with your submissionor form. Please contact support."

    def __init__(self, message=None):
        if message is None:
            self.message = self.default_message
        else:
            self.message = message

    def __str__(self):
        return "{}".format(self.message)


def handle_enketo_error(response):
    """Handle enketo error response."""
    try:
        data = json.loads(response.content)
    except ValueError:
        pass

        if response.status_code == 502:
            raise EnketoError(
                u"Sorry, we cannot load your form right now.  Please try "
                "again later.")
        raise EnketoError()
    else:
        if 'message' in data:
            raise EnketoError(data['message'])
        raise EnketoError(response.text)


def enketo_url(
    form_url, id_string, instance_xml=None,
    instance_id=None,
    return_url=None,
    offline=False
):
    if (not hasattr(settings, 'ENKETO_URL') or
            not hasattr(settings, 'ENKETO_API_SURVEY_PATH') or
            not hasattr(settings, 'ENKETO_API_TOKEN') or
            settings.ENKETO_API_TOKEN == ''):
        return False

    values = {'form_id': id_string, 'server_url': form_url}
    if instance_id and instance_xml:
        url = urljoin(settings.ENKETO_URL, settings.ENKETO_API_INSTANCE_PATH)
        values.update({
            'instance': instance_xml,
            'instance_id': instance_id,
            'return_url': return_url
        })
    else:
        survey_path = settings.ENKETO_API_SURVEY_PATH
        if offline:
            survey_path += '/offline'
        url = urljoin(settings.ENKETO_URL, survey_path)

    response = requests.post(
        url,
        data=values,
        auth=(settings.ENKETO_API_TOKEN, ''),
        verify=getattr(settings, 'ENKETO_VERIFY_SSL', False))
    if response.status_code in (200, 201):
        try:
            data = json.loads(response.content)
        except ValueError:
            pass
        else:
            url = (data.get('edit_url') or data.get('offline_url') or
                   data.get('url'))
            if url:
                return url

    handle_enketo_error(response)


def get_form_url(
    request, protocol='http', preview=False,  # xform_pk=None
):
    """
    Return a form list url endpoint to be used to make a request to Enketo.

    For example, it will return https://example.com and Enketo will know to
    look for the form list at https://example.com/formList. If a username is
    provided then Enketo will request the form list from
    https://example.com/[username]/formList. Same applies for preview if
    preview is True and also to a single form when xform_pk is provided.
    """
    http_host = request.META.get('HTTP_HOST', 'dev.monitora.sisicmbio.icmbio.gov.br')
    url = '%s://%s' % (protocol, http_host)
    if preview:
        url = '%s/preview' % url
    return "{}/xform".format(url)


def get_from_module(module_name, function_name):
    module = importlib.import_module(module_name)
    return getattr(module, function_name)
