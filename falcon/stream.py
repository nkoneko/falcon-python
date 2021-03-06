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

  def __init__(self, url):
    self._url = url

  @property
  def url(self):
    return self._url

class EventStream(object):
  def __init__(self, app_id):
    self.app_id = app_id
    self.refresh = None

  def set_credential(self, autorefreshtoken):
    self.autorefreshtoken = autorefreshtoken

  async def _refresh(self, event):
    while True:
      if self.refresh:
        logger.info('Tries to refresh the active stream')
        res = self.refresh()
        if res.status_code != 200:
          body = res.json()
          logger.error("Failed to refresh an active stream. " + body['errors'][0]['message'])
          raise RuntimeError()
        logger.info('Refresh finished')
      else:
        logger.info('Discover a stream to subscribe')
        discover = DiscoverApi()
        await discover.set_credential(self.autorefreshtoken)
        res = discover(appId=self.app_id)
        if res.status_code != 200:
          body = res.json()
          logger.error("Failed to discover a stream to subscribe. " + body['errors'][0]['message'])
          raise RuntimeError()
        logger.info('Found a stream')
        body = res.json()
        logger.debug(body)
        resources = body['resources'][0]
        self.feed_url = resources['dataFeedURL']
        logger.debug(f'Feed URL: {self.feed_url}')
        self.token = resources['sessionToken']['token']
        logger.debug(f'Token: {self.token}')
        refresh_url = resources['refreshActiveSessionURL']
        logger.debug(f'Refresh URL: {refresh_url}')
        refresh_api = RefreshApi(refresh_url)
        await refresh_api.set_credential(self.autorefreshtoken)
        self.refresh = refresh_api
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
