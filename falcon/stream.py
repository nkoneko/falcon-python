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
    self.refresh_url = None

  def set_credential(self, client_id, client_secret):
    self.client_id = client_id
    self.client_secret = client_secret

  async def _refresh(self, event):
    while True:
      res = requests.post('https://api.crowdstrike.com/oauth2/token', data={
        'client_id': self.client_id,
        'client_secret': self.client_secret
      })
      if res.status_code != 201:
        await asyncio.sleep(5)
        continue
      bearer_token = res.json()['access_token']
      if not self.refresh_url:
        res = requests.get(f'https://api.crowdstrike.com/sensors/entities/datafeed/v2?appId={self.app_id}', headers={
          'Authorization': f'Bearer {bearer_token}'
        })
        if res.status_code != 200:
          await asyncio.sleep(5)
          continue
        resjson = res.json()['resources'][0]
        self.feed_url = resjson['dataFeedURL']
        self.token = resjson['sessionToken']['token']
        self.refresh_url = resjson['refreshActiveSessionURL']
      else:
        res = requests.post(self.refresh_url, headers={
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          'Authorization': f'Bearer {bearer_token}'
        })
        if res.status_code != 200:
          print("failed to refresh streaming session.")
          sys.exit(1)
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
