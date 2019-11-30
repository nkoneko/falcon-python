import logging
import requests
import datetime
import time
import json

logger = logging.getLogger(__name__)

class OAuthBasedApi(object):
  BASE_URL = 'https://api.crowdstrike.com'
  _token = None
  _expiration = datetime.datetime(1970, 1, 1)

  def __init__(self, client_id, client_secret):
    self.client_id = client_id
    self.client_secret = client_secret

  @property
  def url(self):
    path = self.__class__.PATH
    return f'{OAuthBasedApi.BASE_URL}/{path}'

  def _get_token(self):
    max_retries = 3
    now = datetime.datetime.now()
    logger.debug("is token null? => " + str(not OAuthBasedApi._token))
    logger.debug("is token expired? => " +str(OAuthBasedApi._expiration < (now + datetime.timedelta(minutes=10))))
    if (not OAuthBasedApi._token) or (OAuthBasedApi._expiration < (now + datetime.timedelta(minutes=10))):
      token = None
      for _ in range(max_retries):
        logger.info(f'POST {OAuthBasedApi.BASE_URL}/oauth2/token')
        logger.debug(f'OAuth token was requested using this credential ({self.client_id}:{self.client_secret})')
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
        logger.info('OAuth token is successfully generated.')
        j = res.json()
        token = j['access_token']
        logger.debug(f'OAuth token is "{token}"')
        OAuthBasedApi._expiration = now + datetime.timedelta(seconds=j['expires_in'])
        OAuthBasedApi._token = token
        break
      if not token:
        logger.error('Couldn\'t get a token')
        raise RuntimeError()
    return OAuthBasedApi._token

  def get(self, **params):
    params['method'] = 'GET'
    return self.__call__(**params)

  def post(self, **params):
    params['method'] = 'POST'
    return self.__call__(**params)

  def patch(self, **params):
    params['method'] = 'PATCH'
    return self.__call__(**params)

  def delete(self, **params):
    params['method'] = 'DELETE'
    return self.__call__(**params)

  def __call__(self, **params):
    if 'method' in params.keys():
      method = params['method']
    else:
      method = self.__class__.METHOD
    url = self.url
    token = self._get_token()
    auth_header = {'Authorization': f'Bearer {token}'}
    logger.info(f'{method} {url}')
    retries = 3
    while retries > 0:
      if method == 'GET':
        logger.debug('items() -> ' + str(params.items()))
        query = '?' + "&".join(f'{key}={value}' for key, value in params.items())
        logger.debug('Query string => ' + query)
        url = url + query
        logger.debug(f'Detailed request: {method} {url}')
        res = requests.get(url, headers=auth_header)
      elif method == 'POST':
        logger.debug(f'Params: {params}')
        auth_header['Content-Type'] = 'application/json'
        res = requests.post(url, headers=auth_header, data=json.dumps(params))
      elif method == 'PUT':
        logger.debug(f'Params: {params}')
        auth_header['Content-Type'] = 'application/json'
        res = requests.put(url, headers=auth_header, data=json.dumps(params))
      elif method == 'DELETE':
        logger.debug(f'Params: {params}')
        res = requests.delete(url, headers=auth_header, data=json.dumps(params))
      else:
        raise NotImplementedError()
      logger.debug(f'response status code: {res.status_code}')
      if res.status_code == 429:
        logger.warning('Rate Limit Exceeded. Retries will be performed in 3 seconds.')
        time.sleep(3)
        retries = retries - 1
        continue
      return res
    logger.error('Rate Limited.')
    raise RuntimeError()
