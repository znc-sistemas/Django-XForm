import os
import re

from dateutil import parser as pdt
from hashlib import sha256
from xml.parsers.expat import ExpatError

from django.core.exceptions import MultipleObjectsReturned, PermissionDenied
from django.db import IntegrityError, transaction, DataError
from django.db.models import Q
from django.http import UnreadablePostError
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.utils.encoding import DjangoUnicodeDecodeError

from .models import XForm, Instance, Attachment
from .openrosaresponse import OpenRosaResponse, OpenRosaResponseBadRequest
from .openrosaresponse import OpenRosaResponseForbidden
from .openrosaresponse import OpenRosaResponseNotAllowed
from .openrosaresponse import OpenRosaResponseNotFound
from .utils import get_uuid_from_xml, get_meta_from_xml, clean_and_parse_xml
from .utils import (
    DuplicateInstance, InstanceInvalidUserError, InstanceMultipleNodeError,
    InstanceEmptyError, NonUniqueFormIdError, FormIsMergedDatasetError,
    FormInactiveError
)


uuid_regex = re.compile(r'<formhub>\s*<uuid>\s*([^<]+)\s*</uuid>\s*</formhub>',
                        re.DOTALL)


def get_submission_date_from_xml(xml):
    # check in survey_node attributes
    xml = clean_and_parse_xml(xml)
    children = xml.childNodes
    # children ideally contains a single element
    # that is the parent of all survey elements
    if children.length == 0:
        raise ValueError("XML string must have a survey element.")
    survey_node = children[0]
    submissionDate = survey_node.getAttribute('submissionDate')
    if submissionDate != '':
        return pdt.parse(submissionDate)
    return None


def get_id_string_from_xml_str(xml_str):
    xml_obj = clean_and_parse_xml(xml_str)
    root_node = xml_obj.documentElement
    id_string = root_node.getAttribute(u"id")

    if len(id_string) == 0:
        # may be hidden in submission/data/id_string
        elems = root_node.getElementsByTagName('data')

        for data in elems:
            for child in data.childNodes:
                id_string = data.childNodes[0].getAttribute('id')

                if len(id_string) > 0:
                    break

            if len(id_string) > 0:
                break

    return id_string


def get_uuid_from_submission(xml):
    # parse UUID from uploaded XML
    split_xml = uuid_regex.split(xml.decode('utf-8'))

    # check that xml has UUID
    return len(split_xml) > 1 and split_xml[1] or None


def get_xform_from_submission(xml, username, uuid=None):
    # check alternative form submission ids
    uuid = uuid or get_uuid_from_submission(xml)

    if not username and not uuid:
        raise InstanceInvalidUserError()

    if uuid:
        # try find the form by its uuid which is the ideal condition
        if XForm.objects.filter(
                uuid=uuid).count() > 0:
            xform = XForm.objects.get(uuid=uuid,)

            return xform

    id_string = get_id_string_from_xml_str(xml)

    try:
        return get_object_or_404(
            XForm,
            id_string__iexact=id_string
        )
    except MultipleObjectsReturned:
        raise NonUniqueFormIdError()


def check_edit_submission_permissions(request_user, xform):
    return True


def check_submission_permissions(request, xform):
    # TODO
    return True


def get_first_record(queryset):
    """
    Returns the first item in a queryset sorted by id.
    """
    records = sorted([record for record in queryset], key=lambda k: k.id)
    if records:
        return records[0]

    return None


def get_filtered_instances(*args, **kwargs):
    """Get filtered instances - mainly to allow mocking in tests"""

    return Instance.objects.filter(*args, **kwargs)


def update_attachment_tracking(instance):
    """
    Takes an Instance object and updates attachment tracking fields
    """
    instance.skip_signal = True
    instance.total_media = instance.num_of_media
    instance.media_count = instance.attachments_count
    instance.media_all_received = instance.media_count == instance.total_media
    instance.save(update_fields=['total_media', 'media_count',
                                 'media_all_received', 'json'])


def save_attachments(xform, instance, media_files):
    """
    Saves attachments for the given instance/submission.
    """
    # upload_path = os.path.join(instance.xform.user.username, 'attachments')

    for f in media_files:
        filename, extension = os.path.splitext(f.name)
        extension = extension.replace('.', '')
        content_type = u'text/xml' \
            if extension == Attachment.OSM else f.content_type
        if extension == Attachment.OSM and not xform.instances_with_osm:
            xform.instances_with_osm = True
            xform.save()
        filename = os.path.basename(f.name)
        media_in_submission = (
            filename in instance.get_expected_media() or
            instance.xml.decode('utf-8').find(filename) != -1)
        if media_in_submission:
            Attachment.objects.get_or_create(
                instance=instance,
                media_file=f,
                mimetype=content_type,
                name=filename,
                extension=extension)
    update_attachment_tracking(instance)


def get_deprecated_uuid_from_xml(xml):
    uuid = get_meta_from_xml(xml, "deprecatedID")
    regex = re.compile(r"uuid:(.*)")
    if uuid:
        matches = regex.match(uuid)
        if matches and len(matches.groups()) > 0:
            return matches.groups()[0]
    return None


def _get_instance(xml, new_uuid, submitted_by, status, xform, checksum):
    history = None
    instance = None

    if isinstance(xml, bytes):
        xml = xml.decode('utf-8')

    # check if its an edit submission
    old_uuid = get_deprecated_uuid_from_xml(xml)
    if old_uuid:
        instance = Instance.objects.filter(uuid=old_uuid,
                                           xform_id=xform.pk).first()
        if instance:
            # edits
            last_edited = timezone.now()
            instance.xml = xml
            instance.last_edited = last_edited
            instance.uuid = new_uuid
            instance.checksum = checksum
            instance.save()

    if old_uuid is None or (instance is None and history is None):
        # new submission
        instance = Instance(
            xml=xml, user=submitted_by, status=status, xform=xform,
            checksum=checksum)
        instance.skip_signal = False
        instance.save()
    return instance


def save_submission(xform, xml, media_files, new_uuid, submitted_by, status, checksum):
    date_created_override = get_submission_date_from_xml(xml)
    instance = _get_instance(xml, new_uuid, submitted_by, status, xform, checksum)
    save_attachments(xform, instance, media_files)

    # override date created if required
    if date_created_override:
        if not timezone.is_aware(date_created_override):
            # default to utc?
            date_created_override = timezone.make_aware(
                date_created_override, timezone.utc)
        instance.date_created = date_created_override
        instance.save()

    if instance.xform is not None:
        instance.skip_signal = True
        instance.save()
    return instance


def create_instance(
    username,
    xml_file,
    media_files,
    status=u'submitted_via_web',
    uuid=None,
    request=None
):
    """
    I used to check if this file had been submitted already, I've
    taken this out because it was too slow. Now we're going to create
    a way for an admin to mark duplicate instances. This should
    simplify things a bit.
    Submission cases:
    * If there is a username and no uuid, submitting an old ODK form.
    * If there is a username and a uuid, submitting a new ODK form.
    """
    instance = None
    submitted_by = request.user \
        if request and request.user.is_authenticated else None

    if username:
        username = username.lower()

    xml = xml_file.read()
    xform = get_xform_from_submission(xml, username, uuid)
    check_submission_permissions(request, xform)
    checksum = sha256(xml).hexdigest()

    new_uuid = get_uuid_from_xml(xml)
    filtered_instances = get_filtered_instances(
        Q(checksum=checksum) | Q(uuid=new_uuid), xform_id=xform.pk)
    existing_instance = get_first_record(filtered_instances.only('id'))
    if existing_instance and \
            (new_uuid or existing_instance.xform.has_start_time):
        with transaction.atomic():
            save_attachments(xform, existing_instance, media_files)
            existing_instance.save(update_fields=['json', 'date_modified'])
        return DuplicateInstance()

    try:
        with transaction.atomic():
            instance = save_submission(xform, xml, media_files, new_uuid,
                                       submitted_by, status, checksum)
    except IntegrityError:
        instance = get_first_record(Instance.objects.filter(
            Q(checksum=checksum) | Q(uuid=new_uuid),
            xform_id=xform.pk))

        if instance:
            attachment_names = [
                a.media_file.name.split('/')[-1]
                for a in Attachment.objects.filter(instance=instance)
            ]
            media_files = [f for f in media_files
                           if f.name not in attachment_names]
            save_attachments(xform, instance, media_files)
            instance.save()

        instance = DuplicateInstance()
    return instance


def safe_create_instance(username, xml_file, media_files, uuid, request):
    error = instance = None

    try:
        instance = create_instance(
            username, xml_file, media_files, uuid=uuid, request=request)
    except InstanceInvalidUserError:
        error = OpenRosaResponseBadRequest("Username or ID required.")
    except InstanceEmptyError:
        error = OpenRosaResponseBadRequest(
            "Received empty submission. No instance was created")
    except (FormInactiveError, FormIsMergedDatasetError) as e:
        error = OpenRosaResponseNotAllowed(str(e))
    except XForm.DoesNotExist:
        error = OpenRosaResponseNotFound(
            "Form does not exist on this account")
    except ExpatError:
        error = OpenRosaResponseBadRequest("Improperly formatted XML.")
    except DuplicateInstance:
        response = OpenRosaResponse("Duplicate submission")
        response.status_code = 202
        if request:
            response['Location'] = request.build_absolute_uri(request.path)
        error = response
    except PermissionDenied as e:
        error = OpenRosaResponseForbidden(e)
    except UnreadablePostError as e:
        error = OpenRosaResponseBadRequest(
            "Unable to read submitted file: %(error)s" % {'error': str(e)})
    except InstanceMultipleNodeError as e:
        error = OpenRosaResponseBadRequest(e)
    except DjangoUnicodeDecodeError:
        error = OpenRosaResponseBadRequest(
            "File likely corrupted during "
            "transmission, please try later.")
    except NonUniqueFormIdError as e:
        error = OpenRosaResponseBadRequest(
            "Unable to submit because there are multiple forms with"
            " this formID.")
    except DataError as e:
        error = OpenRosaResponseBadRequest((str(e)))
    if isinstance(instance, DuplicateInstance):
        response = OpenRosaResponse("Duplicate submission")
        response.status_code = 202
        if request:
            response['Location'] = request.build_absolute_uri(request.path)
        error = response
        instance = None
    return [error, instance]
