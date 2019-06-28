from django.http import HttpResponse
from django.utils import timezone

OPEN_ROSA_VERSION_HEADER = 'X-OpenRosa-Version'
OPEN_ROSA_VERSION = '1.0'
DEFAULT_CONTENT_TYPE = 'text/xml; charset=utf-8'


class BaseOpenRosaResponse(HttpResponse):
    status_code = 201

    def __init__(self, *args, **kwargs):
        super(BaseOpenRosaResponse, self).__init__(*args, **kwargs)

        self[OPEN_ROSA_VERSION_HEADER] = OPEN_ROSA_VERSION

        dt = timezone.now().strftime('%a, %d %b %Y %H:%M:%S %Z')
        self['Date'] = dt
        self['X-OpenRosa-Accept-Content-Length'] = 10000000
        self['Content-Type'] = DEFAULT_CONTENT_TYPE


class OpenRosaResponse(BaseOpenRosaResponse):
    status_code = 201

    def __init__(self, *args, **kwargs):
        super(OpenRosaResponse, self).__init__(*args, **kwargs)
        self.message = self.content
        # wrap content around xml
        self.content = '''<?xml version='1.0' encoding='UTF-8' ?>
<OpenRosaResponse xmlns="http://openrosa.org/http/response">
        <message nature="">%s</message>
</OpenRosaResponse>''' % self.content


class OpenRosaResponseNotFound(OpenRosaResponse):
    status_code = 404


class OpenRosaResponseBadRequest(OpenRosaResponse):
    status_code = 400


class OpenRosaResponseNotAllowed(OpenRosaResponse):
    status_code = 405


class OpenRosaResponseForbidden(OpenRosaResponse):
    status_code = 403
