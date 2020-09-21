import json

# from pyxform.xls2json import parse_file_to_json
from pyxform.builder import create_survey_element_from_dict

from django.conf import settings
from django.contrib.auth import get_user_model
from django.http import Http404, HttpResponseBadRequest, HttpResponse
from django.http import HttpResponseForbidden, HttpResponseRedirect
from django.http import UnreadablePostError
from django.shortcuts import get_object_or_404
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.cache import never_cache

from rest_framework import permissions
from rest_framework import status
from rest_framework import viewsets
from rest_framework.authentication import BasicAuthentication
from rest_framework.authentication import SessionAuthentication
from rest_framework.authentication import get_authorization_header
from rest_framework.authentication import TokenAuthentication
from rest_framework.decorators import action
from rest_framework.generics import CreateAPIView
from rest_framework.permissions import BasePermission
from rest_framework.response import Response
from rest_framework.settings import api_settings

# from .authentication import DigestAuthentication
from .forms import QuickConverter
from .models import XForm, MetaData, check_version_set
from .openrosaresponse import OpenRosaResponseBadRequest, OPEN_ROSA_ACCEPT_CONTENT_LENGTH
from .renderers import MediaFileContentNegotiation
from .renderers import XFormManifestRenderer, XFormListRenderer
from .serializers import XFormListSerializer, SubmissionSerializer, XFormManifestSerializer
from .tags import GROUP_DELIMETER_TAG, REPEAT_INDEX_TAGS
from .utils import get_media_file_response, publish_form, get_from_module


Usuario = get_user_model()


class CsrfExemptSessionAuthentication(SessionAuthentication):

    def enforce_csrf(self, request):
        return  # To not perform the csrf check previously happening


class IsAuthenticatedSubmission(BasePermission):
    """
    IsAuthenticatedSubmission - checks if profile requires authentication
    during a submission request.
    """

    def has_permission(self, request, view):
        username = view.kwargs.get('username')  # noqa
        if request.method in ['HEAD', 'POST'] and request.user.is_anonymous:
            return False

        return True


def get_forms_shared_with_user(user):
    """
    Return forms shared with a user
    """
    xforms = XForm.objects.filter()

    return xforms.exclude(user=user).select_related('user')


class EnketoODKAuthMixin(object):
    def get_authenticators(self):
        try:
            # check if you are the User-Agent of ODK
            # https://github.com/opendatakit/collect/blob/81b105cef60a113efd1954d782648219ec4733e6/collect_app/src/main/java/org/odk/collect/android/application/Collect.java#L221
            if 'org.odk.collect.android' in self.request.META['HTTP_USER_AGENT']:
                return [BasicAuthentication()]
        except Exception:
            pass
        return [CsrfExemptSessionAuthentication()]


class XLSFormError(Exception):
    pass


class AuthenticateHeaderMixin(object):
    def get_authenticate_header(self, request):
        auth = get_authorization_header(request).split()

        if auth and auth[0].lower() == b'token':
            return TokenAuthentication().authenticate_header(request)

        return super(AuthenticateHeaderMixin, self)\
            .get_authenticate_header(request)


def get_openrosa_headers(request, location=True):
    """
    Returns a dict with OpenRosa headers 'Date', 'X-OpenRosa-Version',
    'X-OpenRosa-Accept-Content-Length' and 'Location'.
    """
    now = timezone.now()
    data = {
        'Date': now.strftime('%a, %d %b %Y %H:%M:%S %Z'),
        'X-OpenRosa-Version': '1.0',
        'X-OpenRosa-Accept-Content-Length': OPEN_ROSA_ACCEPT_CONTENT_LENGTH
    }

    if location:
        data['Location'] = request.build_absolute_uri(request.path).replace('http', 'https')

    return data


class OpenRosaHeadersMixin(object):  # pylint: disable=R0903
    """
    OpenRosaHeadersMixin class - sets OpenRosa headers in a response for a View
    or Viewset.
    """

    def finalize_response(self, request, response, *args, **kwargs):
        """
        Adds OpenRosa headers into the response.
        """
        self.headers.update(get_openrosa_headers(request))

        return super(OpenRosaHeadersMixin, self).finalize_response(
            request, response, *args, **kwargs)


class CreateModelMixin(object):
    """
    Create a model instance.
    """

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    def perform_create(self, serializer):
        serializer.save()

    def get_success_headers(self, data):
        try:
            return {'Location': str(data[api_settings.URL_FIELD_NAME])}
        except (TypeError, KeyError):
            return {}


class XFormListViewSet(EnketoODKAuthMixin, viewsets.ReadOnlyModelViewSet):
    template_name = 'xform/xformsList.xml'
    serializer_class = XFormListSerializer
    permission_classes = (permissions.AllowAny,)
    renderer_classes = (XFormListRenderer,)
    content_negotiation_class = MediaFileContentNegotiation
    queryset = XForm.objects.filter().only(*getattr(
        settings, 'XFORM_ONLY_FILTER', [
            'id_string', 'title', 'version', 'uuid',
            'description', 'hash'
        ]
    ))

    def filter_queryset(self, qs):
        xform_id = self.request.GET.get('formID')
        if xform_id:
            qs = qs.filter(id_string=xform_id)

        qs_filter = getattr(settings, 'XFORM_QS_FILTER', lambda qs, user: qs)

        if isinstance(qs_filter, str):
            module_name, function_name = qs_filter.rsplit(".", 1)
            qs_filter = get_from_module(module_name, function_name)
        return qs_filter(qs, self.request)

    def get_object(self):
        queryset = self.filter_queryset(self.get_queryset())
        filter_kwargs = {self.lookup_field: self.kwargs[self.lookup_field]}
        obj = get_object_or_404(queryset or XForm, **filter_kwargs)
        return obj

    def get_renderers(self):
        if self.action and self.action == 'manifest':
            return [XFormManifestRenderer()]

        return super(XFormListViewSet, self).get_renderers()

    @never_cache
    def list(self, request, *args, **kwargs):
        if self.request.user.is_anonymous:
            self.permission_denied(self.request)

        self.object_list = self.filter_queryset(self.get_queryset())

        headers = get_openrosa_headers(request, location=False)
        serializer = self.get_serializer(self.object_list, many=True)
        if request.method in ['HEAD']:
            return Response('', headers=headers, status=204)

        return Response(serializer.data, headers=headers)

    def retrieve(self, request, *args, **kwargs):
        headers = get_openrosa_headers(request, location=False)
        self.object = self.get_object()
        if self.object.dynamic_choices:
            new_choices = {}
            # survey_dict = parse_file_to_json(
            #     json.loads(self.object.json)['name'],
            #     file_object=self.object.xls
            # )
            survey_dict = json.loads(self.object.json)
            fields_keys = settings.XFORM_DYNAMIC_CHOICES.keys()

            def fill_dynamic_choices(els):
                for field in els:
                    if field['name'] in fields_keys:
                        module_name, function_name = settings.XFORM_DYNAMIC_CHOICES[
                            field['name']
                        ].rsplit(".", 1)
                        f = get_from_module(module_name, function_name)
                        field['children'] = f(request, self.object)
                        new_choices[field['name']] = field['children']

                        if 'choices' in field:
                            field['choices'] = []
                            del field['choices']
                    if field['type'] == 'repeat':
                        fill_dynamic_choices(field['children'])

            fill_dynamic_choices(survey_dict['children'])

            if 'choices' in survey_dict:
                survey_dict['choices'].update(new_choices)
            else:
                survey_dict['choices'] = new_choices

            survey = create_survey_element_from_dict(survey_dict)
            survey = check_version_set(survey)

            return Response(
                survey.to_xml(),
                headers=headers
            )

        return Response(self.object.xml,
                        headers=headers)

    @action(methods=['GET', 'HEAD'], detail=True)
    def manifest(self, request, *args, **kwargs):
        self.object = self.get_object()
        object_list = MetaData.objects.filter(object_id=self.object.pk).filter(
            data_type__in=['media', 'url']
        )
        context = self.get_serializer_context()
        context[GROUP_DELIMETER_TAG] = '.'
        context[REPEAT_INDEX_TAGS] = '_,_'
        serializer = XFormManifestSerializer(object_list, many=True,
                                             context=context)
        return Response(serializer.data,
                        headers=get_openrosa_headers(request, location=False))

    @action(methods=['GET', 'HEAD'], detail=True)
    def media(self, request, *args, **kwargs):
        self.object = self.get_object()
        pk = kwargs.get('metadata')

        if not pk:
            raise Http404()

        meta_obj = get_object_or_404(
            MetaData, data_type__in=['media', 'url'],
            object_id=self.object.pk, pk=pk)
        response = get_media_file_response(
            meta_obj,
            username=self.kwargs['username']
        )

        if response.status_code == 403 and request.user.is_anonymous:
            # raises a permission denied exception, forces authentication
            self.permission_denied(request)
        else:
            return response


class XFormSubmissionView(EnketoODKAuthMixin, OpenRosaHeadersMixin, CreateAPIView):
    '''In the inheritance being a CrateView, but this view is also used for updates.
        The serializer's create method is always called.
        The create method calls a util named create_instance that checks for a
        <deprecatedID> in xml, if there is this tag it will retrieve the instance to be updated.
    '''

    permission_classes = (permissions.IsAuthenticated,)
    serializer_class = SubmissionSerializer
    template_name = 'xform/submission.xml'

    def head(self, request, format=None):
        resp = HttpResponse(b'', status=204)
        return resp

    def handle_exception(self, exc):
        """
        Handles exceptions thrown by handler method and
        returns appropriate error response.
        """
        if hasattr(exc, 'response'):
            return exc.response

        if isinstance(exc, UnreadablePostError):
            return OpenRosaResponseBadRequest(
                "Unable to read submitted file, please try re-submitting.")

        return super(XFormSubmissionView, self).handle_exception(exc)


def profile(request, username):
    content_user = get_object_or_404(Usuario, cpf__iexact=username)
    form = QuickConverter()
    data = {'form': form}

    # xlsform submission...
    if request.method == 'POST' and request.user.is_authenticated:
        def set_form():
            form = QuickConverter(request.POST, request.FILES)
            form.publish(request.user)
        form_result = publish_form(set_form)
        data['message'] = form_result

    if content_user == request.user:
        data.update({
            'form': form,
        })
    try:
        resp = render(request, "xform/profile.html", data)
    except XLSFormError as e:
        resp = HttpResponseBadRequest(e.__str__())

    return resp


def edit(request, username, id_string):
    if not request.method == 'POST':
        return HttpResponseForbidden('Update failed.')

    xform = XForm.objects.get(id_string__iexact=id_string)
    if username == request.user.username or\
            request.user.has_perm('logger.change_xform', xform):

        if request.FILES.get('media'):
            for aFile in request.FILES.getlist("media"):
                MetaData.media_upload(xform, aFile)
        if request.POST.get('media_url'):
            for url in request.POST.getlist("media_url"):
                MetaData.add_url(xform, url)
        xform.save()
        return HttpResponseRedirect(request.GET.get('next_url'))
    return HttpResponseForbidden('Update failed.')
