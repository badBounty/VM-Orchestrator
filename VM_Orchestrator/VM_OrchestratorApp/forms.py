from django import forms

SEVERITY_CHOICES_ENG = [
	('INFORMATIONAL', 'INFORMATIONAL'),
	('LOW', 'LOW'),
    ('MEDIUM', 'MEDIUM'),
    ('HIGH', 'HIGH'),
    ('CRITICAL', 'CRITICAL')
]

SEVERITY_CHOICES_SPA = [
	('INFORMATIONAL', 'INFORMATIONAL'),
	('BAJO', 'BAJO'),
    ('MEDIO', 'MEDIO'),
    ('ALTO', 'ALTO'),
    ('CRITICO', 'CRITICO')
]

class ObservationForm(forms.Form):
    description = forms.CharField(label='Description', required=True, widget=forms.Textarea(attrs={'rows':4, 'cols':40}))
    description_note = forms.CharField(label='Description Note', required=True, widget=forms.Textarea(attrs={'rows':4, 'cols':40}))
    implication = forms.CharField(label='Implication', required=True, widget=forms.Textarea(attrs={'rows':4, 'cols':40}))
    recommendation = forms.CharField(label='Recommendation', required=True, widget=forms.Textarea(attrs={'rows':4, 'cols':40}))
    recommendation_note = forms.CharField(label='Recommendation Notes', required=True, widget=forms.Textarea(attrs={'rows':4, 'cols':40}))
    #
    severity = forms.CharField(label='Severity', widget=forms.Select(choices=SEVERITY_CHOICES_SPA), required=True)

    def populate(self, mongo_obj):
        self.fields['description'].initial = mongo_obj['OBSERVATION']['TITLE']
        self.fields['description_note'].initial = mongo_obj['OBSERVATION']['NOTE']
        self.fields['implication'].initial = mongo_obj['IMPLICATION']
        self.fields['recommendation'].initial = mongo_obj['RECOMMENDATION']['TITLE']
        self.fields['recommendation_note'].initial = mongo_obj['RECOMMENDATION']['URLS']
        #
        choices = SEVERITY_CHOICES_ENG if mongo_obj['LANGUAGE'] == 'eng' else SEVERITY_CHOICES_SPA
        self.fields['severity'].widget.choices = choices

class ApproverForm(forms.Form):
    file = forms.FileField()