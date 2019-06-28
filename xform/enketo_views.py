from django.conf import settings
from django.contrib import messages
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404


from .models import Instance
from .utils import (
    enketo_url, EnketoError, get_form_url, inject_instanceid,
)


def enter_data(request, id_string, offline=False):
    form_url = get_form_url(request, settings.ENKETO_PROTOCOL)
    url = enketo_url(form_url, id_string, offline=offline)
    return HttpResponseRedirect(url)


def edit_data(request, id_string, data_id):
    """
    Redirects to Enketo webform to edit a submission with the data_id.
    """
    return_url_get = request.GET.get('return_url_xform')
    instance = get_object_or_404(
        Instance.objects.only('xml', 'uuid'),
        pk=data_id,
        xform__id_string=id_string
    )

    url = '%sdata/edit_url' % settings.ENKETO_URL
    injected_xml = inject_instanceid(instance.xml, instance.uuid)
    return_url = request.build_absolute_uri(return_url_get)
    form_url = get_form_url(request, settings.ENKETO_PROTOCOL)

    try:
        url = enketo_url(
            form_url,
            id_string,
            instance_xml=injected_xml,
            instance_id=instance.uuid,
            return_url=return_url)
    except EnketoError as e:
        if settings.SENTRY_DSN:
            import sentry_sdk
            sentry_sdk.capture_exception(e)
        messages.error(
            request,
            "Enketo error: enketo replied - %s" % e
        )
    else:
        if url:
            return HttpResponseRedirect(url)
    return HttpResponseRedirect(return_url_get)
