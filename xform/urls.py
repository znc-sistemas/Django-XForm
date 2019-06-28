from django.urls import re_path

from xform import views
from xform import enketo_views


urlpatterns = [
    re_path(
        r'^(?P<id_string>\w+)/enter_data/$',
        enketo_views.enter_data,
        name='enter_data'
    ),
    re_path(
        r'^(?P<id_string>\w+)/enter_data/offline/$',
        enketo_views.enter_data,
        {'offline': True},
        name='enter_data_offline'
    ),
    re_path(
        r'^(?P<id_string>\w+)/edit_data/(?P<data_id>\d+)/$',
        enketo_views.edit_data,
        name='edit_data'
    ),
    re_path(
        r'^(?P<username>[^/]+)/$',
        views.profile,
        name='user_profile'
    ),
    re_path(
        r'^formList$',
        views.XFormListViewSet.as_view({'get': 'list', 'head': 'list'}),
        name='form-list'),
    re_path(
        r'^(?P<username>\w+)/xformsManifest/(?P<pk>[\d+^/]+)$',
        views.XFormListViewSet.as_view({'get': 'manifest', 'head': 'manifest'}),
        name='manifest-url'),
    re_path(
        r'^(?P<username>\w+)/forms/(?P<pk>[\d+^/]+)/form\.xml$',
        views.XFormListViewSet.as_view({'get': 'retrieve', 'head': 'retrieve'}),
        name='download_xform'),
    re_path(
        r'^xformsMedia/(?P<pk>[\d+^/]+)/(?P<metadata>[\d+^/.]+)\.(?P<format>([a-z]|[0-9])*)$',
        views.XFormListViewSet.as_view({'get': 'media', 'head': 'media'}),
        name='xform-media'),
    re_path(
        r'^(?P<username>\w+)/xformsMedia/(?P<pk>[\d+^/]+)/(?P<metadata>[\d+^/.]+)$',
        views.XFormListViewSet.as_view({'get': 'media', 'head': 'media'}),
        name='xform-media'),
    re_path(
        r'^(?P<username>\w+)/xformsMedia/(?P<pk>[\d+^/]+)/(?P<metadata>[\d+^/.]+)\.(?P<format>([a-z]|[0-9])*)$',
        views.XFormListViewSet.as_view({'get': 'media', 'head': 'media'}),
        name='xform-media'),
    re_path(
        r'^xformsMedia/(?P<pk>[\d+^/]+)/(?P<metadata>[\d+^/.]+)$',
        views.XFormListViewSet.as_view({'get': 'media', 'head': 'media'}),
        name='xform-media'),
    re_path(
        r'^submission$',
        views.XFormSubmissionView.as_view(),
        name='submissions'),
    re_path(
        r'^(?P<username>\w+)/(?P<id_string>\w+)/edit/$',
        views.edit,
        name='xform_edit'),
]
