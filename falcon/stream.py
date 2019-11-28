import asyncio
import aiohttp
import requests
import sys
import json
from . import OAuthBasedApi

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
        res = self.refresh()
        if res.status_code != 200:
          print("failed to refresh streaming session")
          sys.exit(1)
      else:
        discover = DiscoverApi(self.client_id, self.client_secret)
        res = discover(appId=self.app_id)
        if res.status_code != 200:
          print("failed to discover stream to subscribe")
          sys.exit(1)
        resources = res.json()['resources'][0]
        self.feed_url = resources['dataFeedURL']
        self.token = resources['sessionToken']['token']
        refresh_url = resources['refreshActiveSessionURL']
        self.refresh = RefreshApi(self.client_id, self.client_secret, refresh_url)
        event.set()
      await asyncio.sleep(25 * 60)

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
            yield event
    await refresh
