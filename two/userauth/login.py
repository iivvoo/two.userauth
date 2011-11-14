import urlparse

from two.ol.base import FormHandler
from two.ol.base import applyrequest

from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import login, logout

class LoginHandler(FormHandler):
    formclass = AuthenticationForm
    template_ns = "two.userauth"

    @applyrequest
    def index(self, redirect_to='/'):
        self.context['redirect_to'] = redirect_to
        return self.template('login.html')

    @applyrequest
    def process(self, redirect_to='/'):
        if self.form.is_valid():
            netloc = urlparse.urlparse(redirect_to)[1]
            if netloc and netloc != self.request.get_host():
                redirect_to = '/'

            login(self.request, self.form.get_user())
            self.redirect(redirect_to, success="Je bent nu ingelogd.")

        if '__all__' in self.form.errors:
            ## assume username/password incorrect
            self.set_message('error', "Gebruikersnaam of wachtwoord incorrect.")
        return self.index()

    @applyrequest
    def handle_logout(self, redirect_to="/login/"):
        logout(self.request)
        self.redirect(redirect_to, success="Je bent nu uitgelogd.")
