from io import BytesIO

from django.utils.xmlutils import SimplerXMLGenerator

from rest_framework import negotiation
from rest_framework.renderers import BaseRenderer, TemplateHTMLRenderer
from rest_framework_xml.renderers import XMLRenderer


FORMLIST_MANDATORY_FIELDS = [
    'formID',
    'name',
    'version',
    'hash',
    'downloadUrl'
]


class XFormListRenderer(BaseRenderer):
    """
    Renderer which serializes to XML.
    """

    media_type = 'text/xml'
    format = 'xml'
    charset = 'utf-8'
    root_node = 'xforms'
    element_node = 'xform'
    xmlns = "http://openrosa.org/xforms/xformsList"

    def render(self, data, accepted_media_type=None, renderer_context=None):
        """
        Renders *obj* into serialized XML.
        """
        if data is None:
            return ''
        elif isinstance(data, str):
            return data

        stream = BytesIO()

        xml = SimplerXMLGenerator(stream, self.charset)
        xml.startDocument()
        xml.startElement(self.root_node, {'xmlns': self.xmlns})

        self._to_xml(xml, data)

        xml.endElement(self.root_node)
        xml.endDocument()

        return stream.getvalue()

    def _to_xml(self, xml, data):
        if isinstance(data, (list, tuple)):
            for item in data:
                xml.startElement(self.element_node, {})
                self._to_xml(xml, item)
                xml.endElement(self.element_node)

        elif isinstance(data, dict):
            for (key, value) in iter(data.items()):
                if key not in FORMLIST_MANDATORY_FIELDS and value is None:
                    continue
                xml.startElement(key, {})
                self._to_xml(xml, value)
                xml.endElement(key)

        elif data is None:
            # Don't output any value
            pass

        else:
            xml.characters(str(data))


class XFormManifestRenderer(XFormListRenderer):  # pylint: disable=R0903
    """
    XFormManifestRenderer - render XFormManifest XML.
    """
    root_node = "manifest"
    element_node = "mediaFile"
    xmlns = "http://openrosa.org/xforms/xformsManifest"


class TemplateXMLRenderer(TemplateHTMLRenderer):  # pylint: disable=R0903
    """
    TemplateXMLRenderer - Render XML template.
    """
    format = 'xml'
    media_type = 'text/xml'

    def render(self, data, accepted_media_type=None, renderer_context=None):
        renderer_context = renderer_context or {}
        response = renderer_context['response']

        if response and response.exception:
            return XMLRenderer().render(data, accepted_media_type,
                                        renderer_context)

        return super(TemplateXMLRenderer,
                     self).render(data, accepted_media_type, renderer_context)


class MediaFileContentNegotiation(negotiation.DefaultContentNegotiation):
    """
    MediaFileContentNegotiation - filters renders to only return renders with
                                  matching format.
    """

    def filter_renderers(self, renderers, format):  # pylint: disable=W0622
        """
        If there is a '.json' style format suffix, filter the renderers
        so that we only negotiation against those that accept that format.
        If there is no renderer available, we use MediaFileRenderer.
        """
        renderers = [
            renderer for renderer in renderers if renderer.format == format
        ]
        if not renderers:
            renderers = [MediaFileRenderer()]

        return renderers


class MediaFileRenderer(BaseRenderer):  # pylint: disable=R0903
    """
    MediaFileRenderer - render binary media files.
    """
    media_type = '*/*'
    format = None
    charset = None
    render_style = 'binary'

    def render(self, data, accepted_media_type=None, renderer_context=None):
        return data
