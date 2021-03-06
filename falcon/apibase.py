import logging
import requests
import time
import json
import asyncio

logger = logging.getLogger(__name__)

class OAuthBasedApi(object):
  BASE_URL = 'https://api.crowdstrike.com'

  async def set_credential(self, autorefreshtoken):
    logger.debug('set auto refresh token')
    await autorefreshtoken.add_api(self)

  def set_token(self, token):
    self.token = token

  @property
  def url(self):
    path = self.__class__.PATH
    return f'{OAuthBasedApi.BASE_URL}/{path}'

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
    token = self.token
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
