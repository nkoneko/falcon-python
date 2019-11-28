import requests
import json

class OAuthBasedApi(object):
  BASE_URL = 'https://api.crowdstrike.com'
  def __init__(self, client_id, client_secret):
    self.client_id = client_id
    self.client_secret = client_secret

  @property
  def url(self):
    path = self.__class__.PATH
    return f'{OAuthBasedApi}/{path}'

  def __call__(self, **params):
    method = self.__class__.METHOD
    url = self.url
    res = requests.post(f'{OAuthBasedApi.BASE_URL}/oauth2/token', data={
      'client_id': self.client_id,
      'client_secret': self.client_secret
    }, headers={
      'Content-Type': 'application/x-www-form-urlencoded'
    })
    if res.status_code != 201
      print("failed to authenticate")
      exit(1)
    token = res.json()['access_token']

    auth_header = {'Authorization': f'Bearer {token}'}
    if method == 'GET':
      query = "&".join(f'{key}={value}' for key, value in params.items())
      url = url + query
      return requests.get(url, headers=auth_header)
    elif method == 'POST':
      return requests.post(url, headers=auth_header, data=json.dumps(params))
    elif method == 'PUT':
      return requests.put(url, headers=auth_header, data=json.dumps(params))
    elif method == 'DELETE':
      return requests.delete(url, headers=auth_header, data=json.dumps(params))
    else:
      raise NotImplementedError()
