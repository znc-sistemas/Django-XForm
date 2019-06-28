from django import forms
from django.db import transaction

from .models import DataDictionary


class QuickConverterFile(forms.Form):
    """
    Uploads XLSForm form.
    """
    xls_file = forms.FileField(
        label='XLS File', required=False)


@transaction.atomic()
def publish_xls_form(xls_file, user, id_string=None, created_by=None):
    """Create or update DataDictionary with xls_file, user
    id_string is optional when updating
    """
    # get or create DataDictionary based on user and id string
    if id_string:
        dd = DataDictionary.objects.get(id_string=id_string)
        dd.xls = xls_file
        dd.save()

        return dd
    else:
        return DataDictionary.objects.create(
            created_by=created_by or user,
            user=user,
            xls=xls_file,
        )


class QuickConverter(QuickConverterFile):
    """
    Publish XLSForm and convert to XForm.
    """

    def publish(self, user, id_string=None, created_by=None):
        """
        Publish XLSForm.
        """
        if self.is_valid():
            # If a text (csv) representation of the xlsform is present,
            # this will save the file and pass it instead of the 'xls_file'
            # field.
            cleaned_xls_file = None

            if 'xls_file' in self.cleaned_data and\
                    self.cleaned_data['xls_file']:
                cleaned_xls_file = self.cleaned_data['xls_file']

            # publish the xls
            return publish_xls_form(
                cleaned_xls_file, user,
                id_string, created_by or user)
