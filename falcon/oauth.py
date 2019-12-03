import asyncio
import contextlib
import aiohttp
import logging

logger = logging.getLogger(__name__)

@contextlib.asynccontextmanager
async def authenticate(client_id, client_secret):
  autorefresh = AutoRefreshToken(client_id, client_secret)
  task = asyncio.create_task(autorefresh.start_refresh())
  yield autorefresh
  task.cancel()

class AutoRefreshToken(object):
  def __init__(self, client_id, client_secret):
    self.client_id = client_id
    self.client_secret = client_secret
    self.apis = []
    self.token = None
    self.wait = 0
    self._lock = asyncio.Lock()

  async def add_api(self, api):
    logger.debug('add api')
    self.apis.append(api)
    await self._lock.acquire()
    if not self.token:
      token = await self._get_token()
      self.token = token
    api.set_token(self.token)
    self._lock.release()
    logger.debug('add api done')

  async def _get_token(self):
    max_retries = 3
    body = None
    url = 'https://api.crowdstrike.com/oauth2/token'
    async with aiohttp.ClientSession(headers={'Content-Type': 'application/x-www-form-urlencoded'}) as session:
      for _ in range(max_retries):
        async with session.post(url, data={ 'client_id': self.client_id, 'client_secret': self.client_secret }) as res:
          if res.status == 429:
            logger.warning('Rate Limit Exceeded. Retries will be performed in 3 seconds.')
            await asyncio.sleep(3)
          elif res.status == 201:
            body = await res.json()
            break
          else:
            body = await res.json()
            logger.error('Cannot authenticate.' + body['errors'][0]['message'])
      if not body:
        logger.error('Could\'nt get a token')
        raise RuntimeError()
      token = body['access_token']
      self.wait = max(body['expires_in'] - 60 * 5, 60 * 5)
    return token

  async def start_refresh(self):
    while True:
      await asyncio.sleep(self.wait)
      logger.debug('start refresh')
      await self._lock.acquire()
      logger.debug('start refresh -> lock acquired')
      token = await self._get_token()
      logger.debug(f'OAuth token is "{token}"')
      self.token = token
      for api in self.apis:
        api.set_token(token)
      self._lock.release()
