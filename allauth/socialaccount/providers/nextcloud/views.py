import requests
import xml.etree.ElementTree as ET

from django.conf import settings

from allauth.socialaccount.providers.oauth2.views import (
    OAuth2Adapter,
    OAuth2CallbackView,
    OAuth2LoginView,
)

from .provider import NextCloudProvider


class NextCloudAdapter(OAuth2Adapter):
    provider_id = NextCloudProvider.id
    access_token_url = f'{settings.NEXTCLOUD_SERVER}/apps/oauth2/api/v1/token'
    authorize_url = f'{settings.NEXTCLOUD_SERVER}/apps/oauth2/authorize'
    profile_url = f'{settings.NEXTCLOUD_SERVER}/ocs/v1.php/cloud/users/'

    def complete_login(self, request, app, token, **kwargs):
        extra_data = self.get_user_info(token, kwargs['response']['user_id'])
        return self.get_provider().sociallogin_from_response(request, extra_data)

    def get_user_info(self, token, user_id):
        resp = requests.get(self.profile_url + user_id, headers={'Authorization': f'Bearer {token}'})
        resp.raise_for_status()
        root = ET.fromstring(resp.content.decode())
        return {child.tag: child.text.strip() for child in root[1] if child.text is not None}


oauth2_login = OAuth2LoginView.adapter_view(NextCloudAdapter)
oauth2_callback = OAuth2CallbackView.adapter_view(NextCloudAdapter)
