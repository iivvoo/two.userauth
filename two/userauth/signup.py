from two.ol.base import FormHandler, applyrequest
from django import forms
from django.utils.translation import ugettext_lazy as _
from django.contrib.auth.models import User

from two.userauth.reset import send_reset

import hashlib

class RegistrationForm(forms.Form):
    email = forms.EmailField(label=_("E-mail"), max_length=75)

    def clean_email(self):
        email = self.cleaned_data["email"].strip().lower()
        try:
            User.objects.get(username=email)
        except User.DoesNotExist:
            return email
        raise forms.ValidationError(_("A user with that email already exists."))

class SignupHandler(FormHandler):
    formclass = RegistrationForm
    url = "/signup/"
    template_ns = "two.userauth"

    def index(self):
        self.context['redirect_to'] = "/"
        return self.template("register.html")

    def get_username(self, form):
        """ email is not suitable as username, generate a hash in stead """
        email = form.data['email']
        return hashlib.md5(email).hexdigest()
        
    @applyrequest
    def process(self, redirect_to="/"):
        if self.form.is_valid():
            ## in this case @applyform would be nice?
            email = self.form.data['email']
            username = self.get_username(self.form)

            u = User(username=username, email=email)
            u.set_unusable_password()
            u.save()
            send_reset(self, u, initial=True)
            self.redirect(redirect_to, success="Aanmelding succesvol, verdere instructies zijn per email verstuurd.")
        return self.index()

