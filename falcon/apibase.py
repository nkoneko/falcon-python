import logging
import requests
import datetime
import time
import json

logger = logging.getLogger(__name__)

class OAuthBasedApi(object):
  BASE_URL = 'https://api.crowdstrike.com'
  _token_exp = datetime.datetime(1970, 1, 1)
  _token = None

  def __init__(self, client_id, client_secret):
    self.client_id = client_id
    self.client_secret = client_secret

  @property
  def url(self):
    path = self.__class__.PATH
    return f'{OAuthBasedApi.BASE_URL}/{path}'

  def _get_token(self):
    now = datetime.datetime.now()
    if not OAuthBasedApi._token or OAuthBasedApi._token_exp < (now + datetime.timedelta(seconds=180)):
      max_retries = 3
      for _ in range(max_retries):
        res = requests.post(f'{OAuthBasedApi.BASE_URL}/oauth2/token', data={
          'client_id': self.client_id,
          'client_secret': self.client_secret
        }, headers={
          'Content-Type': 'application/x-www-form-urlencoded'
        })
        if res.status_code == 429:
          logger.warning('Rate Limit Exceeded. Retries will be performed in 3 seconds.')
          time.sleep(3)
          continue
        if res.status_code != 201:
          logger.error('Cannot authenticate.' + res.json()['errors'][0]['message'])
          raise RuntimeError()
        j = res.json()
        token = j['access_token']
        OAuthBasedApi._token_exp = now + datetime.timedelta(seconds=j['expires_in'])
        OAuthBasedApi._token = token
        break
      if not token:
        logger.error('Couldn\'t get a token')
        raise RuntimeError()
    return OAuthBasedApi._token

  def __call__(self, **params):
    method = self.__class__.METHOD
    url = self.url
    token = self._get_token()
    auth_header = {'Authorization': f'Bearer {token}'}
    retries = 3
    while retries > 0:
      if method == 'GET':
        query = '?' + "&".join(f'{key}={value}' for key, value in params.items())
        url = url + query
        res = requests.get(url, headers=auth_header)
      elif method == 'POST':
        res = requests.post(url, headers=auth_header, data=json.dumps(params))
      elif method == 'PUT':
        res = requests.put(url, headers=auth_header, data=json.dumps(params))
      elif method == 'DELETE':
        res = requests.delete(url, headers=auth_header, data=json.dumps(params))
      else:
        raise NotImplementedError()
      if res.status_code == 429:
        logger.warning('Rate Limit Exceeded. Retries will be performed in 3 seconds.')
        time.sleep(3)
        retries = retries - 1
        continue
      return res
    logger.error('Rate Limited.')
    raise RuntimeError()
