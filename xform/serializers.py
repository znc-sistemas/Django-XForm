import mimetypes

from functools import wraps

from django.conf import settings

from rest_framework import exceptions
from rest_framework import serializers
from rest_framework.reverse import reverse

from .models import MetaData
from .safe_create_instance import safe_create_instance
from .tags import GROUP_DELIMETER_TAG, REPEAT_INDEX_TAGS
from .utils import get_file_extension


def get_request_and_username(context):
    """
    Returns request object and username
    """
    request = context['request']
    view = context['view']
    username = view.kwargs.get('username')

    if not username:
        # get the username from the user if not set
        username = (request.user and request.user.username)

    return (request, username)


def check_obj(f):
    @wraps(f)
    def with_check_obj(*args, **kwargs):
        if args[0]:
            return f(*args, **kwargs)

    return with_check_obj


class XFormListSerializer(serializers.Serializer):
    formID = serializers.ReadOnlyField(source='id_string')
    name = serializers.ReadOnlyField(source='title')
    version = serializers.SerializerMethodField()
    hash = serializers.ReadOnlyField(source='random_hash' if settings.XFORM_RANDOM_HASH else 'hash')
    descriptionText = serializers.ReadOnlyField(source='description')
    downloadUrl = serializers.SerializerMethodField('get_url')
    manifestUrl = serializers.SerializerMethodField('get_manifest_url')

    @check_obj
    def get_version(self, obj):
        if obj.version and obj.version.isdigit():
            return obj.version

    @check_obj
    def get_url(self, obj):
        request = self.context.get('request')
        kwargs = {'pk': obj.pk, 'username': request.user.username}
        return reverse('download_xform', kwargs=kwargs, request=request)

    @check_obj
    def get_manifest_url(self, obj):
        request = self.context.get('request')
        kwargs = {'pk': obj.pk, 'username': request.user.username}
        object_list = MetaData.objects.filter(data_type__in=('media', 'url'),
                                              object_id=obj.pk)
        if object_list:
            return reverse('manifest-url', kwargs=kwargs, request=request)
        return None


class XFormManifestSerializer(serializers.Serializer):
    filename = serializers.SerializerMethodField()
    hash = serializers.SerializerMethodField()
    downloadUrl = serializers.SerializerMethodField('get_url')

    @check_obj
    def get_url(self, obj):
        request = self.context.get('request')
        username = self.context['view'].kwargs['username']
        kwargs = {
            'pk': obj.content_object.pk,
            'username': username,
            'metadata': obj.pk
        }
        try:
            fmt = obj.data_value[obj.data_value.rindex('.') + 1:]
            if obj.data_type == 'url':
                ct, enc = mimetypes.guess_type(fmt)
                if not ct:
                    file_data = obj.file(username=username)
                    fmt = get_file_extension(file_data.content_type)
        except ValueError:
            fmt = 'csv'
        url = reverse(
            'xform-media', kwargs=kwargs, request=request, format=fmt.lower())

        group_delimiter = self.context.get(GROUP_DELIMETER_TAG)
        repeat_index_tags = self.context.get(REPEAT_INDEX_TAGS)
        if group_delimiter and repeat_index_tags and fmt == 'csv':
            url = (url + "?%s=%s&%s=%s" % (
                GROUP_DELIMETER_TAG, group_delimiter, REPEAT_INDEX_TAGS,
                repeat_index_tags))
        return url

    @check_obj
    def get_hash(self, obj):
        if obj.data_type == 'url':
            file_data = obj.file(username=self.context['view'].kwargs['username'])
            hmd5 = MetaData.get_md5(file_data)
            return hmd5
        return obj.file_hash

    @check_obj
    def get_filename(self, obj):
        if obj.data_type == 'url':
            file_data = obj.file(username=self.context['view'].kwargs['username'])
            return file_data.name
        return obj.data_value


class SubmissionSuccessMixin(object):  # pylint: disable=R0903
    """
    SubmissionSuccessMixin - prepares submission success data/message.
    """

    def to_representation(self, instance):
        """
        Returns a dict with a successful submission message.
        """
        if instance is None:
            return super(SubmissionSuccessMixin, self)\
                .to_representation(instance)

        return {
            'message': "Recebido com sucesso.",
            'formid': instance.xform.id_string,
            'encrypted': False,
            'instanceID': u'uuid:%s' % instance.uuid,
            'submissionDate': instance.date_created.isoformat(),
            'markedAsCompleteDate': instance.date_modified.isoformat()
        }


class SubmissionSerializer(SubmissionSuccessMixin, serializers.Serializer):
    """
    XML SubmissionSerializer - handles creating a submission from XML.
    """

    def validate(self, attrs):
        request, __ = get_request_and_username(self.context)
        if not request.FILES or 'xml_submission_file' not in request.FILES:
            raise serializers.ValidationError("No XML submission file.")

        return super(SubmissionSerializer, self).validate(attrs)

    def create(self, validated_data):
        """
        Returns object instances based on the validated data
        """
        request, username = get_request_and_username(self.context)

        xml_file_list = request.FILES.pop('xml_submission_file', [])
        xml_file = xml_file_list[0] if xml_file_list else None
        media_files = request.FILES.values()

        error, instance = safe_create_instance(username, xml_file, media_files,
                                               None, request)
        if error:
            exc = exceptions.APIException(detail=error)
            exc.response = error
            exc.status_code = error.status_code

            raise exc

        return instance
