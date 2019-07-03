import csv
import json
import mimetypes
import os
import random
import re

import requests
import xlrd

from contextlib import closing
from hashlib import md5
from io import BytesIO
from io import StringIO


from pyxform import SurveyElementBuilder
from pyxform.builder import create_survey_element_from_dict
from pyxform.utils import has_external_choices
from pyxform.xform2json import create_survey_element_from_xml
from pyxform.xls2json import parse_file_to_json

from xml.dom import Node

from django.conf import settings
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.fields import GenericRelation
from django.contrib.contenttypes.models import ContentType
from django.contrib.gis.db import models
from django.contrib.gis.geos import GeometryCollection, Point
from django.contrib.postgres.fields import JSONField
from django.core.exceptions import ValidationError
from django.core.files.temp import NamedTemporaryFile
from django.core.files.uploadedfile import InMemoryUploadedFile
from django.core.validators import URLValidator
from django.db.models.signals import post_save
from django.utils import timezone


from .tags import (
    UUID, ID, ATTACHMENTS, STATUS, NOTES, VERSION, DURATION, XFORM_ID_STRING,
    XFORM_ID, GEOLOCATION, SUBMITTED_BY, SUBMISSION_TIME, TOTAL_MEDIA,
    MEDIA_COUNT, MEDIA_ALL_RECEIVED, EDITED, LAST_EDITED, KNOWN_MEDIA_TYPES,
    START, END
)
from .utils import (
    get_values_matching_key, get_uuid_from_xml, set_uuid, XFormInstanceParser,
    clean_and_parse_xml, get_numeric_fields, numeric_checker,
    _get_tag_or_element_type_xpath, calculate_duration
)

CHUNK_SIZE = 1024
XFORM_TITLE_LENGTH = 255
title_pattern = re.compile(r"<h:title>(.*?)</h:title>")


def contains_xml_invalid_char(text, invalids=['&', '>', '<']):
    """Check whether 'text' contains ANY invalid xml chars"""
    return 1 in [c in text for c in invalids]


def convert_to_serializable_date(date):
    if hasattr(date, 'isoformat'):
        return date.isoformat()
    return date


def _get_attachments_from_instance(instance):
    attachments = []
    for a in instance.attachments.all():
        attachment = dict()
        attachment['download_url'] = a.media_file.url
        attachment['small_download_url'] = a.media_file.url
        attachment['medium_download_url'] = a.media_file.url
        attachment['mimetype'] = a.mimetype
        attachment['filename'] = a.media_file.name
        attachment['name'] = a.name
        attachment['instance'] = a.instance.pk
        attachment['xform'] = instance.xform.id
        attachment['id'] = a.id
        attachments.append(attachment)

    return attachments


def get_default_content_type():
    content_object, created = ContentType.objects.get_or_create(
        app_label="xform", model='xform')
    return content_object.id


def upload_to(instance, filename):
    try:
        return os.path.join(
            instance.user.username, 'xls',
            os.path.split(filename)[1])
    except Exception:
        folder = "{}_{}".format(instance.instance.xform.id,
                                instance.instance.xform.id_string)
        return os.path.join(
            instance.instance.xform.user.username, 'attachments', folder,
            os.path.split(filename)[1])


class XLSFormError(Exception):
    pass


class FormInactiveError(Exception):
    pass


class XForm(models.Model):
    dynamic_choices = True

    xls = models.FileField(upload_to=upload_to, null=True)
    json = models.TextField(default=u'')
    description = models.TextField(default=u'', null=True, blank=True)
    xml = models.TextField()

    user = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='xforms', null=True, on_delete=models.CASCADE)

    id_string = models.SlugField(
        editable=False,
        verbose_name="ID",
        max_length=100)
    title = models.CharField(editable=False, max_length=255)
    date_created = models.DateTimeField(auto_now_add=True)
    date_modified = models.DateTimeField(auto_now=True)

    last_submission_time = models.DateTimeField(blank=True, null=True)
    has_start_time = models.BooleanField(default=False)
    uuid = models.CharField(max_length=36, default=u'')

    uuid_regex = re.compile(r'(<instance>.*?id="[^"]+">)(.*</instance>)(.*)',
                            re.DOTALL)
    instance_id_regex = re.compile(r'<instance>.*?id="([^"]+)".*</instance>',
                                   re.DOTALL)

    instances_with_geopoints = models.BooleanField(default=False)

    num_of_submissions = models.IntegerField(default=0)

    version = models.CharField(
        max_length=255, null=True, blank=True)

    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.CASCADE)

    metadata_set = GenericRelation(
        'MetaData',
        content_type_field='content_type_id',
        object_id_field="object_id")

    has_hxl_support = models.BooleanField(default=False)
    last_updated_at = models.DateTimeField(auto_now=True)
    hash = models.CharField("Hash", max_length=36, blank=True, null=True,
                            default=None)

    class Meta:
        unique_together = ("user", "id_string",)
        verbose_name = "XForm"
        verbose_name_plural = "XForms"
        ordering = ("pk", )

    def get_osm_survey_xpaths(self):
        """
        Returns abbreviated_xpath for OSM question types in the survey.
        """
        return [
            elem.get_abbreviated_xpath()
            for elem in self.get_survey_elements_of_type('osm')]

    def get_media_survey_xpaths(self):
        return [
            e.get_abbreviated_xpath()
            for e in sum([
                self.get_survey_elements_of_type(m) for m in KNOWN_MEDIA_TYPES
            ], [])
        ]

    def file_name(self):
        return self.id_string + ".xml"

    def get_survey_elements_of_type(self, element_type):
        return [
            e for e in self.get_survey_elements() if e.type == element_type
        ]

    def _set_uuid_in_xml(self, file_name=None):
        """
        Add bind to automatically set UUID node in XML.
        """
        if not file_name:
            file_name = self.file_name()
        file_name, file_ext = os.path.splitext(file_name)
        doc = clean_and_parse_xml(self.xml)
        model_nodes = doc.getElementsByTagName("model")
        if len(model_nodes) != 1:
            raise Exception(u"xml contains multiple model nodes")

        model_node = model_nodes[0]
        instance_nodes = [
            node for node in model_node.childNodes
            if node.nodeType == Node.ELEMENT_NODE and
            node.tagName.lower() == "instance" and not node.hasAttribute("id")
        ]

        if len(instance_nodes) != 1:
            raise Exception("Multiple instance nodes without the id "
                            "attribute, can't tell which is the main one")

        instance_node = instance_nodes[0]

        # get the first child whose id attribute matches our id_string
        survey_nodes = [
            node for node in instance_node.childNodes
            if node.nodeType == Node.ELEMENT_NODE and
            (node.tagName == file_name or node.attributes.get('id'))
        ]

        if len(survey_nodes) != 1:
            raise Exception(
                "Multiple survey nodes with the id '%s'" % self.id_string)

        survey_node = survey_nodes[0]
        formhub_nodes = [
            n for n in survey_node.childNodes
            if n.nodeType == Node.ELEMENT_NODE and n.tagName == "formhub"
        ]

        if len(formhub_nodes) > 1:
            raise Exception(
                "Multiple formhub nodes within main instance node")
        elif len(formhub_nodes) == 1:
            formhub_node = formhub_nodes[0]
        else:
            formhub_node = survey_node.insertBefore(
                doc.createElement("formhub"), survey_node.firstChild)

        uuid_nodes = [
            node for node in formhub_node.childNodes
            if node.nodeType == Node.ELEMENT_NODE and node.tagName == "uuid"
        ]

        if len(uuid_nodes) == 0:
            formhub_node.appendChild(doc.createElement("uuid"))
        if len(formhub_nodes) == 0:
            # append the calculate bind node
            calculate_node = doc.createElement("bind")
            calculate_node.setAttribute(
                "nodeset", "/%s/formhub/uuid" % survey_node.tagName)
            calculate_node.setAttribute("type", "string")
            calculate_node.setAttribute("calculate", "'%s'" % self.uuid)
            model_node.appendChild(calculate_node)

        self.xml = doc.toprettyxml(indent="  ", encoding='utf-8')
        # hack
        # http://ronrothman.com/public/leftbraned/xml-dom-minidom-toprettyxml-\
        # and-silly-whitespace/
        text_re = re.compile('(>)\n\s*(\s[^<>\s].*?)\n\s*(\s</)', re.DOTALL)
        output_re = re.compile('\n.*(<output.*>)\n(  )*')
        pretty_xml = text_re.sub(lambda m: ''.join(m.group(1, 2, 3)),
                                 self.xml.decode('utf-8'))
        inline_output = output_re.sub('\g<1>', pretty_xml)
        inline_output = re.compile('<label>\s*\n*\s*\n*\s*</label>').sub(
            '<label></label>', inline_output)
        self.xml = inline_output

    def _mark_start_time_boolean(self):
        starttime_substring = 'jr:preloadParams="start"'
        if self.xml.find(starttime_substring) != -1:
            self.has_start_time = True
        else:
            self.has_start_time = False

    def _id_string_already_exists_in_account(self, id_string):
        try:
            XForm.objects.get(user=self.user, id_string__iexact=id_string)
        except XForm.DoesNotExist:
            return False

        return True

    def get_unique_id_string(self, id_string, count=0):
        # used to generate a new id_string for new data_dictionary object if
        # id_string already existed
        if self._id_string_already_exists_in_account(id_string):
            if count != 0:
                if re.match(r'\w+_\d+$', id_string):
                    a = id_string.split('_')
                    id_string = "_".join(a[:-1])
            count += 1
            id_string = "{}_{}".format(id_string, count)

            return self.get_unique_id_string(id_string, count)

        return id_string

    def _set_title(self):
        xml = re.sub(r"\s+", " ", self.xml)
        matches = title_pattern.findall(xml)

        if len(matches) != 1:
            raise XLSFormError(("There should be a single title."), matches)

        if matches:
            title_xml = matches[0][:XFORM_TITLE_LENGTH]
        else:
            title_xml = self.title[:XFORM_TITLE_LENGTH] if self.title else ''

        if self.title and title_xml != self.title:
            title_xml = self.title[:XFORM_TITLE_LENGTH]
            if isinstance(self.xml, bytes):
                self.xml = self.xml.decode('utf-8')
            self.xml = title_pattern.sub(u"<h:title>%s</h:title>" % title_xml,
                                         self.xml)
            self._set_hash()
        if contains_xml_invalid_char(title_xml):
            raise XLSFormError(
                "Title shouldn't have any invalid xml "
                "characters ('>' '&' '<')"
            )

        self.title = title_xml

    def get_hash(self):
        return u'md5:%s' % md5(self.xml.encode('utf8')).hexdigest()

    def get_random_hash(self):
        return u'md5:%s' % md5(
            ("%s-%s" % (
                self.xml,
                random.randint(0, 25101991)
            )).encode('utf8')
        ).hexdigest()

    @property
    def random_hash(self):
        return self.get_random_hash()

    def _set_hash(self):
        self.hash = self.get_hash()

    def _set_id_string(self):
        matches = self.instance_id_regex.findall(self.xml)
        if len(matches) != 1:
            raise XLSFormError("There should be a single id string.")
        self.id_string = matches[0]

    def save(self, *args, **kwargs):
        update_fields = kwargs.get('update_fields')
        if update_fields:
            kwargs['update_fields'] = list(
                set(list(update_fields) + ['date_modified']))
        if update_fields is None or 'title' in update_fields:
            self._set_title()
        if self.pk is None:
            self._set_hash()
        if update_fields is None or 'id_string' in update_fields:
            old_id_string = self.id_string
            self._set_id_string()
            # check if we have an existing id_string,
            # if so, the one must match but only if xform is NOT new
            if self.pk and old_id_string and old_id_string != self.id_string \
                    and self.num_of_submissions > 0:
                raise XLSFormError(
                    "Your updated form's id_string '%(new_id)s' must match "
                    "the existing forms' id_string '%(old_id)s'." % {
                        'new_id': self.id_string,
                        'old_id': old_id_string
                    })
            if getattr(settings, 'STRICT', True) and \
                    not re.search(r"^[\w-]+$", self.id_string):
                raise XLSFormError(
                    'In strict mode, the XForm ID must be a '
                    'valid slug and contain no spaces.')

        if 'skip_xls_read' in kwargs:
            del kwargs['skip_xls_read']

        super(XForm, self).save(*args, **kwargs)

    def get_survey(self):
        if not hasattr(self, "_survey"):
            try:
                builder = SurveyElementBuilder()
                self._survey = \
                    builder.create_survey_element_from_json(self.json)
            except ValueError:
                xml = bytes(bytearray(self.xml, encoding='utf-8'))
                self._survey = create_survey_element_from_xml(xml)
        return self._survey

    survey = property(get_survey)

    def get_survey_elements(self):
        return self.survey.iter_descendants()

    def geopoint_xpaths(self):
        survey_elements = self.get_survey_elements()

        return [
            e.get_abbreviated_xpath() for e in survey_elements
            if e.bind.get(u'type') == u'geopoint'
        ]

    def __str__(self):
        return self.id_string


def type_for_form(content_object, data_type):
    content_type = ContentType.objects.get_for_model(content_object)
    return MetaData.objects.filter(object_id=content_object.id,
                                   content_type=content_type,
                                   data_type=data_type)


def is_valid_url(uri):
    try:
        URLValidator(uri)
    except ValidationError:
        return False

    return True


def create_media(media):
    """Download media link"""
    if is_valid_url(media.data_value):
        filename = media.data_value.split('/')[-1]
        data_file = NamedTemporaryFile()
        content_type = mimetypes.guess_type(filename)
        with closing(requests.get(media.data_value, stream=True)) as r:
            for chunk in r.iter_content(chunk_size=CHUNK_SIZE):
                if chunk:
                    data_file.write(chunk)
        data_file.seek(os.SEEK_SET, os.SEEK_END)
        size = os.path.getsize(data_file.name)
        data_file.seek(os.SEEK_SET)
        media.data_value = filename
        media.data_file = InMemoryUploadedFile(
            data_file, 'data_file', filename, content_type,
            size, charset=None)

        return media

    return None


def media_resources(media_list, download=False):
    """List of MetaData objects of type media

    @param media_list - list of MetaData objects of type `media`
    @param download - boolean, when True downloads media files when
    media.data_value is a valid url

    return a list of MetaData objects

    """
    data = []
    for media in media_list:
        if media.data_file.name == '' and download:
            media = create_media(media)

            if media:
                data.append(media)
        else:
            data.append(media)

    return data


def meta_data_upload_to(instance, filename):
    username = None

    if instance.content_object.user is None and \
            instance.content_type.model == 'instance':
        username = instance.content_object.xform.user.username
    else:
        username = instance.content_object.user.username

    if instance.data_type == 'media':
        return os.path.join(username, 'formid-media', filename)

    return os.path.join(username, 'docs', filename)


class MetaData(models.Model):
    data_type = models.CharField(max_length=255)
    data_value = models.CharField(max_length=255)
    data_file = models.FileField(upload_to=meta_data_upload_to, blank=True, null=True)
    data_file_type = models.CharField(max_length=255, blank=True, null=True)
    file_hash = models.CharField(max_length=50, blank=True, null=True)
    date_created = models.DateTimeField(null=True, auto_now_add=True)
    date_modified = models.DateTimeField(null=True, auto_now=True)
    deleted_at = models.DateTimeField(null=True, default=None)
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE,
                                     default=get_default_content_type)
    object_id = models.PositiveIntegerField(null=True, blank=True)
    content_object = GenericForeignKey('content_type', 'object_id')

    objects = models.Manager()

    class Meta:
        unique_together = ('object_id', 'data_type', 'data_value',
                           'content_type')

    def __str__(self):
        return self.data_value

    def file(self, username=None):
        if hasattr(self, '_file'):
            return self._file

        url = requests.Request(
            'GET', self.data_value, params={
                'username': username
            }
        ).prepare().url
        self._file = MetaData.get_file(url)
        return self._file

    @staticmethod
    def media_upload(content_object, data_file=None, download=False):
        data_type = 'media'
        if data_file:
            allowed_types = settings.XFORM_SUPPORTED_MEDIA_UPLOAD_TYPES
            data_content_type = data_file.content_type \
                if data_file.content_type in allowed_types else \
                mimetypes.guess_type(data_file.name)[0]

            if data_content_type in allowed_types:
                content_type = ContentType.objects.get_for_model(
                    content_object)

                media, created = MetaData.objects.update_or_create(
                    data_type=data_type,
                    content_type=content_type,
                    object_id=content_object.id,
                    data_value=data_file.name,
                    defaults={
                        'data_file': data_file,
                        'data_file_type': data_content_type
                    })
        return media_resources(
            type_for_form(content_object, data_type), download)

    @staticmethod
    def get_md5(data_file):
        hash_md5 = md5()
        for chunk in iter(lambda: data_file.read(4096), b""):
            hash_md5.update(chunk)
        return 'md5:%s' % hash_md5.hexdigest()

    @staticmethod
    def get_file(url):
        data_file = None
        output = BytesIO()

        def getsize(f):
            f.seek(0)
            f.read()
            s = f.tell()
            f.seek(0)
            return s

        r = requests.get(url, allow_redirects=True)
        d = r.headers['content-disposition']
        fname = re.findall("filename=\"(.+)\"", d)[0]
        content_type = r.headers.get('content-type')
        output.write(r.content)
        size = getsize(output)
        data_file = InMemoryUploadedFile(
            file=output, name=fname,
            field_name=None,
            content_type=content_type,
            charset='utf-8', size=size
        )
        return data_file

    @staticmethod
    def add_url(content_object, url=None, download=False):
        data_type = 'url'
        try:
            data_file = MetaData.get_file(url)
        except Exception:
            return None

        allowed_types = settings.XFORM_SUPPORTED_MEDIA_UPLOAD_TYPES
        data_content_type = data_file.content_type \
            if data_file.content_type in allowed_types else \
            mimetypes.guess_type(data_file.name)[0]

        if data_content_type in allowed_types:
            content_type = ContentType.objects.get_for_model(
                content_object)

            media, created = MetaData.objects.update_or_create(
                data_type=data_type,
                content_type=content_type,
                object_id=content_object.id,
                data_value=url,
                defaults={
                    'data_file': None,
                    'data_file_type': data_content_type
                })
        return media_resources(
            type_for_form(content_object, data_type), download)

    def save(self, *args, **kwargs):
        self._set_hash()
        super(MetaData, self).save(*args, **kwargs)

    @property
    def hash(self):
        if self.file_hash is not None and self.file_hash != '':
            return self.file_hash
        else:
            return self._set_hash()

    def _set_hash(self):
        if not self.data_file:
            return None

        file_exists = self.data_file.storage.exists(self.data_file.name)

        if (file_exists and self.data_file.name != '') \
                or (not file_exists and self.data_file):
            try:
                self.data_file.seek(os.SEEK_SET)
            except IOError:
                return ''
            else:
                self.file_hash = 'md5:%s' % md5(
                    self.data_file.read()).hexdigest()

                return self.file_hash

        return ''


class Instance(models.Model):
    """
    Model representing a single submission to an XForm
    """

    json = JSONField(default=dict, null=False)
    xml = models.TextField()
    user = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='instances', null=True, on_delete=models.CASCADE)
    xform = models.ForeignKey('xform.XForm', null=False,
                              related_name='instances', on_delete=models.CASCADE)

    # shows when we first received this instance
    date_created = models.DateTimeField(auto_now_add=True)

    # this will end up representing "date last parsed"
    date_modified = models.DateTimeField(auto_now=True)

    # this will be edited when we need to create a new InstanceHistory object
    last_edited = models.DateTimeField(null=True, default=None)

    # ODK keeps track of three statuses for an instance:
    # incomplete, submitted, complete
    # we add a fourth status: submitted_via_web
    status = models.CharField(max_length=20,
                              default=u'submitted_via_web')
    uuid = models.CharField(max_length=249, default=u'', db_index=True)
    version = models.CharField(max_length=255, null=True)

    # store a geographic objects associated with this instance
    geom = models.GeometryCollectionField(null=True)

    # Keep track of whether all media attachments have been received
    media_all_received = models.NullBooleanField(
        "Received All Media Attachemts",
        null=True,
        default=True)
    total_media = models.PositiveIntegerField("Total Media Attachments",
                                              null=True,
                                              default=0)
    media_count = models.PositiveIntegerField("Received Media Attachments",
                                              null=True,
                                              default=0)
    checksum = models.CharField(max_length=64, null=True, blank=True,
                                db_index=True)

    class Meta:
        unique_together = ('xform', 'uuid')

    def __str__(self):
        return "Status: %s" % self.status

    @property
    def point(self):
        gc = self.geom

        if gc and len(gc):
            return gc[0]

    def get_duration(self):
        data = self.get_dict()
        # pylint: disable=no-member
        start_name = _get_tag_or_element_type_xpath(self.xform, START)
        end_name = _get_tag_or_element_type_xpath(self.xform, END)
        start_time, end_time = data.get(start_name), data.get(end_name)

        return calculate_duration(start_time, end_time)

    @property
    def num_of_media(self):
        """
        Returns number of media attachments expected in the submission.
        """
        if not hasattr(self, '_num_of_media'):
            # pylint: disable=attribute-defined-outside-init
            self._num_of_media = len(self.get_expected_media())

        return self._num_of_media

    @property
    def attachments_count(self):
        return self.attachments.filter(
            name__in=self.get_expected_media()
        ).distinct('name').order_by('name').count()

    def get_expected_media(self):
        """
        Returns a list of expected media files from the submission data.
        """
        if not hasattr(self, '_expected_media'):
            # pylint: disable=no-member
            data = self.get_dict()
            media_list = []
            if 'encryptedXmlFile' in data and self.xform.encrypted:
                media_list.append(data['encryptedXmlFile'])
                if 'media' in data:
                    # pylint: disable=no-member
                    media_list.extend([i['media/file'] for i in data['media']])
            else:
                media_xpaths = (self.xform.get_media_survey_xpaths() +
                                self.xform.get_osm_survey_xpaths())
                for media_xpath in media_xpaths:
                    media_list.extend(
                        get_values_matching_key(data, media_xpath))
            # pylint: disable=attribute-defined-outside-init
            self._expected_media = list(set(media_list))

        return self._expected_media

    def numeric_converter(self, json_dict, numeric_fields=None):
        if numeric_fields is None:
            # pylint: disable=no-member
            numeric_fields = get_numeric_fields(self.xform)
        for key, value in json_dict.items():
            if isinstance(value, (str, bytes)) and key in numeric_fields:
                converted_value = numeric_checker(value)
                if converted_value:
                    json_dict[key] = converted_value
            elif isinstance(value, dict):
                json_dict[key] = self.numeric_converter(
                    value, numeric_fields)
            elif isinstance(value, list):
                for k, v in enumerate(value):
                    if isinstance(v, (str, bytes)) and key in numeric_fields:
                        converted_value = numeric_checker(v)
                        if converted_value:
                            json_dict[key] = converted_value
                    elif isinstance(v, dict):
                        value[k] = self.numeric_converter(
                            v, numeric_fields)
        return json_dict

    def _set_geom(self):
        # pylint: disable=no-member
        xform = self.xform
        geo_xpaths = xform.geopoint_xpaths()
        doc = self.get_dict()
        points = []

        if geo_xpaths:
            for xpath in geo_xpaths:
                for gps in get_values_matching_key(doc, xpath):
                    try:
                        geometry = [float(s) for s in gps.split()]
                        lat, lng = geometry[0:2]
                        points.append(Point(lng, lat))
                    except ValueError:
                        return

            if not xform.instances_with_geopoints and len(points):
                xform.instances_with_geopoints = True
                xform.save()

            self.geom = GeometryCollection(points)

    def _check_active(self, force):
        """Check that form is active and raise exception if not.

        :param force: Ignore restrictions on saving.
        """
        # pylint: disable=no-member
        # if not force and self.xform and not self.xform.downloadable:
        #     raise FormInactiveError()
        pass

    def _set_json(self):
        self.json = self.get_full_dict()

    def get_full_dict(self, load_existing=True):
        doc = self.json or {} if load_existing else {}
        # Get latest dict
        doc = self.get_dict()
        # pylint: disable=no-member
        if self.id:
            doc.update({
                UUID: self.uuid,
                ID: self.id,
                # BAMBOO_DATASET_ID: self.xform.bamboo_dataset,
                ATTACHMENTS: _get_attachments_from_instance(self),
                STATUS: self.status,
                # TAGS: list(self.tags.names()),
                NOTES: [],
                VERSION: self.version,
                DURATION: self.get_duration(),
                XFORM_ID_STRING: self._parser.get_xform_id_string(),
                XFORM_ID: self.xform.pk,
                GEOLOCATION: [self.point.y, self.point.x] if self.point
                else [None, None],
                SUBMITTED_BY: self.user.username if self.user else None
            })

            # for osm in self.osm_data.all():
            #     doc.update(osm.get_tags_with_prefix())
            if not self.date_created:
                self.date_created = timezone.now()

            doc[SUBMISSION_TIME] = self.date_created.strftime('%Y-%m-%dT%H:%M:%S')

            doc[TOTAL_MEDIA] = self.total_media
            doc[MEDIA_COUNT] = self.media_count
            doc[MEDIA_ALL_RECEIVED] = self.media_all_received

            edited = False
            if hasattr(self, 'last_edited'):
                edited = self.last_edited is not None

            doc[EDITED] = edited
            edited and doc.update({
                LAST_EDITED: convert_to_serializable_date(self.last_edited)
            })
        return doc

    def get_dict(self, force_new=False, flat=True):
        """Return a python object representation of this instance's XML."""
        self._set_parser()

        instance_dict = self._parser.get_flat_dict_with_attributes() if flat \
            else self._parser.to_dict()
        return self.numeric_converter(instance_dict)

    def _set_survey_type(self):
        self.survey_type = self.get_root_node_name()

    def _set_parser(self):
        if not hasattr(self, "_parser"):
            # pylint: disable=no-member
            self._parser = XFormInstanceParser(self.xml, self.xform)

    def get_root_node_name(self):
        self._set_parser()
        return self._parser.get_root_node_name()

    def _set_uuid(self):
        # pylint: disable=no-member, attribute-defined-outside-init
        if self.xml and not self.uuid:
            # pylint: disable=no-member
            uuid = get_uuid_from_xml(self.xml)
            if uuid is not None:
                self.uuid = uuid
        set_uuid(self)

    def save(self, *args, **kwargs):
        force = kwargs.get('force')

        if force:
            del kwargs['force']

        # self._check_is_merged_dataset()
        self._check_active(force)
        self._set_geom()
        self._set_json()
        self._set_survey_type()
        self._set_uuid()
        # pylint: disable=no-member
        self.version = self.json.get(VERSION, self.xform.version)

        super(Instance, self).save(*args, **kwargs)


class Attachment(models.Model):
    OSM = 'osm'

    instance = models.ForeignKey(
        Instance, related_name="attachments", on_delete=models.CASCADE)
    media_file = models.FileField(
        max_length=255, upload_to=upload_to)
    mimetype = models.CharField(
        max_length=100, null=False, blank=True, default='')
    extension = models.CharField(
        max_length=10, null=False, blank=False, default=u"non", db_index=True)
    date_created = models.DateTimeField(null=True, auto_now_add=True)
    date_modified = models.DateTimeField(null=True, auto_now=True)

    file_size = models.PositiveIntegerField(default=0)
    name = models.CharField(max_length=100, null=True, blank=True)

    class Meta:
        ordering = ("pk", )

    def save(self, *args, **kwargs):
        if self.media_file and self.mimetype == '':
            # guess mimetype
            mimetype, encoding = mimetypes.guess_type(self.media_file.name)
            if mimetype:
                self.mimetype = mimetype
        if self.media_file and len(self.media_file.name) > 255:
            raise ValueError(
                "Length of the media file should be less or equal to 255")

        try:
            f_size = self.media_file.size
            if f_size:
                self.file_size = f_size
        except (OSError, AttributeError):
            pass

        try:
            self.name = self.filename
            self.extension = self.name.rsplit('.', 1)[1]
        except Exception:
            pass

        super(Attachment, self).save(*args, **kwargs)

    @property
    def file_hash(self):
        if self.media_file.storage.exists(self.media_file.name):
            return u'%s' % md5(self.media_file.read()).hexdigest()
        return u''

    @property
    def filename(self):
        if self.media_file:
            return os.path.basename(self.media_file.name)


def is_newline_error(e):
    """
    Return True is e is a new line error based on the error text.
    Otherwise return False.
    """
    newline_error = u'new-line character seen in unquoted field - do you need'\
        u' to open the file in universal-newline mode?'
    return newline_error == str(e)


def process_xlsform(xls, default_name):
    """
    Process XLSForm file and return the survey dictionary for the XLSForm.
    """
    # FLOW Results package is a JSON file.

    file_object = None
    if xls.name.endswith('csv'):
        # a csv file gets closed in pyxform, make a copy
        xls.seek(0)
        file_object = BytesIO()
        file_object.write(xls.read())
        file_object.seek(0)
        xls.seek(0)

    try:
        return parse_file_to_json(xls.name, file_object=file_object or xls)
    except csv.Error as e:
        if is_newline_error(e):
            xls.seek(0)
            file_object = StringIO(
                u'\n'.join(xls.read().splitlines()))
            return parse_file_to_json(
                xls.name, default_name=default_name, file_object=file_object)
        raise e


def get_columns_with_hxl(survey_elements):
    '''
    Returns a dictionary whose keys are xform field names and values are
    `instance::hxl` values set on the xform
    :param include_hxl - boolean value
    :param survey_elements - survey elements of an xform
    return dictionary or None
    '''
    return survey_elements and {
        se.get('name'): val.get('hxl')
        for se in survey_elements
        for key, val in se.items()
        if key == 'instance' and val and 'hxl' in val
    }


def check_version_set(survey):
    """
    Checks if the version has been set in the xls file and if not adds
    the default version in this datetime (yyyymmddhhmm) format.
    """

    # get the json and check for the version key
    survey_json = json.loads(survey.to_json())
    if not survey_json.get("version"):
        # set utc time as the default version
        survey_json['version'] = \
            timezone.now().strftime("%Y%m%d%H%M")
        builder = SurveyElementBuilder()
        survey = builder.create_survey_element_from_json(
            json.dumps(survey_json))
    return survey


class DataDictionary(XForm):  # pylint: disable=too-many-instance-attributes
    """
    DataDictionary model class.
    """

    def __init__(self, *args, **kwargs):
        self.instances_for_export = lambda d: d.instances.all()
        self.has_external_choices = False
        self._id_string_changed = False
        super(DataDictionary, self).__init__(*args, **kwargs)

    def __str__(self):
        return getattr(self, "id_string", "")

    def save(self, *args, **kwargs):
        skip_xls_read = kwargs.get('skip_xls_read')

        if self.xls and not skip_xls_read:
            default_name = None \
                if not self.pk else self.survey.xml_instance().tagName
            survey_dict = process_xlsform(self.xls, default_name)
            if has_external_choices(survey_dict):
                self.has_external_choices = True
            survey = create_survey_element_from_dict(survey_dict)
            survey = check_version_set(survey)
            if get_columns_with_hxl(survey.get('children')):
                self.has_hxl_support = True
            # if form is being replaced, don't check for id_string uniqueness
            if self.pk is None:
                new_id_string = self.get_unique_id_string(
                    survey.get('id_string'))
                self._id_string_changed = \
                    new_id_string != survey.get('id_string')
                survey['id_string'] = new_id_string
                # For flow results packages use the user defined id/uuid
            elif self.id_string != survey.get('id_string'):
                raise XLSFormError(
                    ("Your updated form's id_string '%(new_id)s' must match "
                     "the existing forms' id_string '%(old_id)s'." % {
                         'new_id': survey.get('id_string'),
                         'old_id': self.id_string}))
            elif default_name and default_name != survey.get('name'):
                survey['name'] = default_name
            else:
                survey['id_string'] = self.id_string
            self.json = survey.to_json()
            self.xml = survey.to_xml()
            self.version = survey.get('version')
            self.last_updated_at = timezone.now()
            self.title = survey.get('title')
            self._mark_start_time_boolean()
            set_uuid(self)
            self._set_uuid_in_xml()
            self._set_hash()

        if 'skip_xls_read' in kwargs:
            del kwargs['skip_xls_read']

        super(DataDictionary, self).save(*args, **kwargs)

    def file_name(self):
        return os.path.split(self.xls.name)[-1]


def sheet_to_csv(xls_content, sheet_name):
    """Writes a csv file of a specified sheet from a an excel file

    :param xls_content: Excel file contents
    :param sheet_name: the name of the excel sheet to generate the csv file

    :returns: a (StrionIO) csv file object
    """
    workbook = xlrd.open_workbook(file_contents=xls_content)

    sheet = workbook.sheet_by_name(sheet_name)

    if not sheet or sheet.nrows < 2:
        raise Exception("Sheet <'%(sheet_name)s'> has no data." % {
            'sheet_name': sheet_name})

    csv_file = BytesIO()

    writer = csv.writer(csv_file, encoding='utf-8', quoting=csv.QUOTE_ALL)
    mask = [v and len(v.strip()) > 0 for v in sheet.row_values(0)]

    header = [v for v, m in zip(sheet.row_values(0), mask) if m]
    writer.writerow(header)

    name_column = None
    try:
        name_column = header.index('name')
    except ValueError:
        pass

    integer_fields = False
    date_fields = False
    if name_column:
        name_column_values = sheet.col_values(name_column)
        for index in range(len(name_column_values)):
            if sheet.cell_type(index, name_column) == xlrd.XL_CELL_NUMBER:
                integer_fields = True
            elif sheet.cell_type(index, name_column) == xlrd.XL_CELL_DATE:
                date_fields = True

    for row in range(1, sheet.nrows):
        if integer_fields or date_fields:
            # convert integers to string/datetime if name has numbers/dates
            row_values = []
            for index, val in enumerate(sheet.row_values(row)):
                if sheet.cell_type(row, index) == xlrd.XL_CELL_NUMBER:
                    try:
                        val = str(
                            float(val) if (
                                float(val) > int(val)
                            ) else int(val)
                        )
                    except ValueError:
                        pass
                elif sheet.cell_type(row, index) == xlrd.XL_CELL_DATE:
                    val = xlrd.xldate_as_datetime(
                        val, workbook.datemode).isoformat()
                row_values.append(val)
            writer.writerow([v for v, m in zip(row_values, mask) if m])
        else:
            writer.writerow(
                [v for v, m in zip(sheet.row_values(row), mask) if m])

    return csv_file


def set_object_permissions(sender, instance=None, created=False, **kwargs):
    """
    Apply the relevant object permissions for the form to all users who should
    have access to it.
    """
    # seems the super is not called, have to get xform from here
    xform = XForm.objects.get(pk=instance.pk)

    if hasattr(instance, 'has_external_choices') \
            and instance.has_external_choices:
        instance.xls.seek(0)
        f = sheet_to_csv(instance.xls.read(), 'external_choices')
        f.seek(0, os.SEEK_END)
        size = f.tell()
        f.seek(0)

        data_file = InMemoryUploadedFile(
            file=f,
            field_name='data_file',
            name='itemsets.csv',
            content_type='text/csv',
            size=size,
            charset=None
        )

        MetaData.media_upload(xform, data_file)


post_save.connect(set_object_permissions, sender=DataDictionary,
                  dispatch_uid='xform_object_permissions')
