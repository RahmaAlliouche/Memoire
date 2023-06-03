from django import forms
from .models import Request

class RequestForm(forms.ModelForm):
    class Meta:
        model = Request
        fields = [ 'date', 'time']

    def __init__(self, *args, **kwargs):
        self.requester = kwargs.pop('requester')
        super().__init__(*args, **kwargs)

    def save(self, commit=True):
        instance = super().save(commit=False)
        instance.requester = self.requester
        if commit:
            instance.save()
        return instance
