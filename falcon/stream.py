import logging
import asyncio
import aiohttp
import requests
import json
from .apibase import OAuthBasedApi

logger = logging.getLogger(__name__)

class DiscoverApi(OAuthBasedApi):
  METHOD = 'GET'
  PATH = '/sensors/entities/datafeed/v2'

class RefreshApi(OAuthBasedApi):
  METHOD = 'POST'
  def __init__(self, client_id, client_secret, url):
    super().__init__(client_id, client_secret)
    self._url = url

  @property
  def url(self):
    return self._url

class EventStream(object):
  def __init__(self, app_id):
    self.app_id = app_id
    self.refresh = None

  def set_credential(self, client_id, client_secret):
    self.client_id = client_id
    self.client_secret = client_secret

  async def _refresh(self, event):
    while True:
      if self.refresh:
        logger.info('Tries to refresh the active stream')
        res = self.refresh()
        if res.status_code != 200:
          logger.error("Failed to refresh an active stream. " + res.json()['errors'][0]['message'])
          raise RuntimeError()
        logger.info('Refresh finished')
      else:
        logger.info('Discover a stream to subscribe')
        discover = DiscoverApi(self.client_id, self.client_secret)
        res = discover(appId=self.app_id)
        if res.status_code != 200:
          logger.error("Failed to discover a stream to subscribe. " + res.json()['errors'][0]['message'])
          raise RuntimeError()
        logger.info('Found a stream')
        resources = res.json()['resources'][0]
        self.feed_url = resources['dataFeedURL']
        logger.debug(f'Feed URL: {self.feed_url}')
        self.token = resources['sessionToken']['token']
        logger.debug(f'Token: {self.token}')
        refresh_url = resources['refreshActiveSessionURL']
        logger.debug(f'Refresh URL: {refresh_url}')
        self.refresh = RefreshApi(self.client_id, self.client_secret, refresh_url)
        event.set()
      await asyncio.sleep(25 * 60)
      event.clear()

  async def retrieve_event(self, offset=0):
    refreshed = asyncio.Event()
    refresh = asyncio.create_task(self._refresh(refreshed))
    await refreshed.wait()
    async with aiohttp.ClientSession(headers={'Authorization': f'Token {self.token}'}, timeout=None) as session:
      async with session.get(self.feed_url, timeout=None) as res:
        async for line in res.content:
          line = line.strip()
          if line:
            event = json.loads(line)
            if event['metadata']['offset'] < offset:
              continue
            logger.debug('offset: ' + str(event['metadata']['offset']))
            yield event
    await refresh
