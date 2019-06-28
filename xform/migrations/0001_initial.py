# Generated by Django 2.2 on 2019-04-29 18:54

from django.conf import settings
import django.contrib.gis.db.models.fields
import django.contrib.postgres.fields.jsonb
from django.db import migrations, models
import django.db.models.deletion
import xform.models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('contenttypes', '0002_remove_content_type_name'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='XForm',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('xls', models.FileField(null=True, upload_to=xform.models.upload_to)),
                ('json', models.TextField(default='')),
                ('description', models.TextField(blank=True, default='', null=True)),
                ('xml', models.TextField()),
                ('id_string', models.SlugField(editable=False, max_length=100, verbose_name='ID')),
                ('title', models.CharField(editable=False, max_length=255)),
                ('date_created', models.DateTimeField(auto_now_add=True)),
                ('date_modified', models.DateTimeField(auto_now=True)),
                ('last_submission_time', models.DateTimeField(blank=True, null=True)),
                ('has_start_time', models.BooleanField(default=False)),
                ('uuid', models.CharField(default='', max_length=36)),
                ('instances_with_geopoints', models.BooleanField(default=False)),
                ('num_of_submissions', models.IntegerField(default=0)),
                ('version', models.CharField(blank=True, max_length=255, null=True)),
                ('has_hxl_support', models.BooleanField(default=False)),
                ('last_updated_at', models.DateTimeField(auto_now=True)),
                ('hash', models.CharField(blank=True, default=None, max_length=36, null=True, verbose_name='Hash')),
                ('created_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
                ('user', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='xforms', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'XForm',
                'verbose_name_plural': 'XForms',
                'ordering': ('pk',),
                'unique_together': {('user', 'id_string')},
            },
        ),
        migrations.CreateModel(
            name='MetaData',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('data_type', models.CharField(max_length=255)),
                ('data_value', models.CharField(max_length=255)),
                ('data_file', models.FileField(blank=True, null=True, upload_to=xform.models.upload_to)),
                ('data_file_type', models.CharField(blank=True, max_length=255, null=True)),
                ('file_hash', models.CharField(blank=True, max_length=50, null=True)),
                ('date_created', models.DateTimeField(auto_now_add=True, null=True)),
                ('date_modified', models.DateTimeField(auto_now=True, null=True)),
                ('deleted_at', models.DateTimeField(default=None, null=True)),
                ('object_id', models.PositiveIntegerField(blank=True, null=True)),
                ('content_type', models.ForeignKey(default=xform.models.get_default_content_type, on_delete=django.db.models.deletion.CASCADE, to='contenttypes.ContentType')),
            ],
            options={
                'unique_together': {('object_id', 'data_type', 'data_value', 'content_type')},
            },
        ),
        migrations.CreateModel(
            name='Instance',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('json', django.contrib.postgres.fields.jsonb.JSONField(default=dict)),
                ('xml', models.TextField()),
                ('date_created', models.DateTimeField(auto_now_add=True)),
                ('date_modified', models.DateTimeField(auto_now=True)),
                ('last_edited', models.DateTimeField(default=None, null=True)),
                ('status', models.CharField(default='submitted_via_web', max_length=20)),
                ('uuid', models.CharField(db_index=True, default='', max_length=249)),
                ('version', models.CharField(max_length=255, null=True)),
                ('geom', django.contrib.gis.db.models.fields.GeometryCollectionField(null=True, srid=4326)),
                ('media_all_received', models.NullBooleanField(default=True, verbose_name='Received All Media Attachemts')),
                ('total_media', models.PositiveIntegerField(default=0, null=True, verbose_name='Total Media Attachments')),
                ('media_count', models.PositiveIntegerField(default=0, null=True, verbose_name='Received Media Attachments')),
                ('checksum', models.CharField(blank=True, db_index=True, max_length=64, null=True)),
                ('user', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='instances', to=settings.AUTH_USER_MODEL)),
                ('xform', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='instances', to='xform.XForm')),
            ],
            options={
                'unique_together': {('xform', 'uuid')},
            },
        ),
    ]
