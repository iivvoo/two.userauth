from two.ol.base import FormHandler, applyrequest
from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import SetPasswordForm
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth import login, authenticate

from django.utils.translation import ugettext_lazy as _
from django.utils.http import int_to_base36
from django.utils.http import base36_to_int

from django.contrib.sites.models import get_current_site
from django.core.mail import send_mail

from django.conf import settings

## more generically: password handler?

class ForgottenForm(forms.Form):
    username = forms.EmailField(label=_("Username"), max_length=75)

    def clean_username(self):
        username = self.cleaned_data["username"].strip().lower()
        try:
            User.objects.get(username=username)
        except User.DoesNotExist:
            raise forms.ValidationError(_("No user is known with this email address/username."))
        return username

def send_reset(handler, user, initial=False):
    remote_addr = handler.request.META.get('X_FORWARDED_FOR')
    if remote_addr is None:
        remote_addr = handler.request.META.get('REMOTE_ADDR')

    if initial:
        email_template_name = "initial_password_main.html"
        subject = "Registratie op %s"
    else:
        email_template_name = "reset_password_main.html"
        subject = "Wachtwoordherstel voor %s"

    from_email = settings.MAIL_SENDER
    token_generator = default_token_generator

    #if is_admin_site:
    #    opts = dict(opts, domain_override=request.META['HTTP_HOST'])
    current_site = get_current_site(handler.request)
    site_name = current_site.name
    domain = current_site.domain
    use_https = handler.request.is_secure()

    t = handler.render_template(email_template_name,
        email=user.email,
        domain=domain,
        site_name=site_name,
        uid=int_to_base36(user.id),
        user=user,
        token=token_generator.make_token(user),
        protocol=use_https and 'https' or 'http',
        remote_addr=remote_addr
    )
    
    send_mail(_(subject) % site_name, t, from_email, [user.email]) 


class ResetHandler(FormHandler):
    formclass = None # SetPasswordForm
    template_ns = "two.userauth"

    def get_user(self, uidb36, token):
        try:
            uid_int = base36_to_int(uidb36)
            user = User.objects.get(id=uid_int)
            if user and default_token_generator.check_token(user, token):
                return user
        except (ValueError, User.DoesNotExist):
            pass
        return None

    @applyrequest
    def index(self, username="", redirect_to="/"):
        self.context['form'] = self.form = ForgottenForm(initial={'username':username})
        self.context['redirect_to'] = redirect_to or '/'
        return self.template("forgotten.html")

    @applyrequest
    def handle_forgotten(self, username, redirect_to="/"):
        self.context['form'] = self.form = ForgottenForm(data=self.request.POST)
        if self.form.is_valid():
            user = User.objects.get(username=self.form.data['username'])
            send_reset(self, user)
            self.redirect(redirect_to or "/", success="Instructies om je wachtwoord te herstellen zijn per e-mail verstuurd.")

        return self.template("forgotten.html")
        
    @applyrequest
    def handle_confirm(self, uidb36, token, initial=False):
        user = self.get_user(uidb36, token)
        self.context['form'] = self.form = SetPasswordForm(user)
        return self.template("reset.html", 
                             redirect_to="/manage/",
                             user=user, 
                             validlink=(user is not None), 
                             uidb36=uidb36, 
                             token=token,
                             initial=initial)

    @applyrequest
    def process(self, uidb36, token, redirect_to="/", initial=False, auto_login=True):
        user = self.get_user(uidb36, token)
        self.context['form'] = self.form = SetPasswordForm(user, self.request.POST)
        if user is not None:
            if self.form.is_valid():
                self.form.save()
                if auto_login:
                    password = self.form.data['new_password1']
                    user = authenticate(username=user.username, 
                                        password=password)
                    login(self.request, user)
                self.redirect(redirect_to, success="Wachtwoord is ingesteld.")
        ## XXX applyrequest/applicator can't handle positional arguments
        ## but it will hapilly apply the request variables again, anyway
        # return self.index(uidb36, token, initial)
        # return self.index(uidb36=uidb36, token=token, initial=initial)
        # return self.handle_confirm()
        return self.template("reset.html", 
                             user=user, 
                             redirect_to=redirect_to,
                             validlink=(user is not None), 
                             uidb36=uidb36, 
                             token=token,
                             initial=initial)
       
    def handle_complete(self):
        # XXX deprecated?
        return self.template("complete.html")
