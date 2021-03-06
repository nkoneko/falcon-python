Python client library for accessing CrowdStrike Falcon APIs
==============================================================

Dependencies
-------------

* Python >= 3.7
* aiohttp
* requests

Installation
-------------

To install falcon-python, clone this repositoty and simply use setup.py

```
$ git clone https://github.com/nkoneko/falcon-python
$ cd falcon-python
$ python setup.py install
```

Usage
--------

This library is under development, and so far it provides with only low-level implementation.
No API doc is available.

### Detects API

```python
from falcon.detects import DetectsQueryAPI, DetectsSummaryAPI
from falcon import oauth

query = DetectsQueryAPI()
summary = DetectsSummaryAPI()

async def get_detection_summaries(q, offset, limit):
  async with oauth.authenticate(CLIENT_ID, CLIENT_SECRET) as token:
    await query.set_credential(token)
    await summary.set_credential(token)
    resources = query.get(q=q, offset=offset, limit=limit)
    for r in resources:
      yield summary.get(ids=r)
    while query.has_next():
      resources = query.fetch_next()
      for r in resources:
        yield summary.get(ids=r)
```

### Streaming API

```python
from falcon.stream import EventStream
from falcon import oauth

stream = EventStream(APP_ID)

async def print_events():
  async with oauth.authenticate(CLIENT_ID, CLIENT_SECRET) as token:
    stream.set_credential(token)
    async for event in stream.retrieve_event(offset=OFFSET):
      print(event)
```

Examples
-----------

Code examples can be found under `examples/`.
You can use `examples/slack.py` to subscribe an event stream and post security events on slack.

```
$ python examples/slack.py $APP_ID $CLIENT_ID $CLIENT_SECRET --offset /path/to/file/to/read-write/offset --webhook $SLACK_INCOMING_HOOK_URL --log /path/to/log
```

Before using the streaming API, make sure the streaming API is enabled on your environment. If it's not enabled, you must contact the CrowdStrike support team.
