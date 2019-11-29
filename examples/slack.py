import asyncio
import argparse
import logging, logging.handlers
import requests
import json
import sys
from datetime import datetime, timedelta, timezone
from falcon.stream import EventStream

JST = timezone(timedelta(hours=9))
logger = logging.getLogger(__name__)

def _compose(pdv, blocked):
  kills = []
  blocks = []
  if pdv & 16:
    kills.append('the process')
  if pdv & 512:
    kills.append('the parent process')
  if pdv & 1024:
    blocks.append('suspicious operations')
  if pdv & 2048:
    blocks.append('execution')
  if pdv & 4096:
    blocks.append('suspicious registry operations')
  desc = ''
  if blocked:
    desc = ':shield: '
  desc = desc + 'Falcon '
  if pdv == 0:
    desc = desc + 'detects a suspicious process.'
  else:
    if not blocked:
      detects = kills + blocks
      desc = desc + "detected (and would have killed/blocked, if related policy was enabled) "
      if len(detects) > 1:
        desc = desc + " and ".join([", ".join(detects[:-1]), detects[-1]]) + "."
      else:
        desc = desc + detects[0] + "."
    else:
      if len(kills):
        desc = desc + 'killed ' + " and ".join(kills)
      if len(blocks):
        if desc[-1] != ' ':
          desc = desc + ", and "
        desc = desc + "blocked " + " and ".join(blocks)
      desc = desc + "."
  return desc

def _slack_payload_d(event):
  e = event['event']
  short_keys = ['FileName', 'SeverityName', 'ComputerName', 'UserName', 'LocalIP', 'Tactic', 'Technique', 'Objective']
  long_keys = ['CommandLine', 'DetectDescription']
  colors = ['#3498db', '#3498db', '#3498db', 'warning', 'danger', 'danger']
  color = colors[e['Severity']]
  pdv = e['PatternDispositionValue']
  blocked = not (pdv & 256) and (not (pdv & 14))
  description = _compose(pdv, blocked)
  title = ("[Prevention] " if blocked else "[Detection] ") + e['FileName']
  fields = []
  for k in short_keys:
    fields.append({ 'title': k, 'value': e[k], 'short': True })
  for k in long_keys:
    fields.append({ 'title': k, 'value': e[k], 'short': False })
  fields.append({ 'title': 'Description', 'value': description, 'short': False })
  return {
    'attachments': [{
      'fallback': f"{title} - {description}",
      'color': color,
      'title': title,
      'title_link': e['FalconHostLink'],
      'fields': fields,
      'ts': int(event['metadata']['eventCreationTime']/1000)
    }]
  }

def _slack_payload_a(event):
  e = event['event']
  if e['ServiceName'] == 'Crowdstrike Authentication':
    if e['OperationName'] == 'saml2Assert':
      text = e['UserId']
      if e['Success']:
        text = text + ' logged in.'
      else:
        text = text + ' failed to log in.'
      text = text + ' IP Address: ' + e['UserIp']
      text = text + ', Timestamp: ' + datetime.fromtimestamp(e['UTCTimestamp'], JST).strftime('%Y-%m-%d %H:%M:%S %z')
      return { 'text': text }
  if e['OperationName'] == 'streamStarted' or e['OperationName'] == 'streamStopped':
    return None
  title = 'Authentication Event'
  fields = [
    { 'title': 'OperationName', 'value': e['OperationName'], 'short': True },
    { 'title': 'UserId', 'value': e['UserId'], 'short': True },
    { 'title': 'UserIp', 'value': e['UserIp'], 'short': True }
  ]
  tstext = datetime.fromtimestamp(e['UTCTimestamp'], JST).strftime('%Y-%m-%d %H:%M:%S %z')
  for _e in e['AuditKeyValues']:
    fields.append({ 'title': _e['Key'], 'value': _e['ValueString'], 'short': True })
  return {
    'attachments': [{
      'fallback': f"{title}, {e['OperationName']} - {e['UserId']}, {e['UserIp']}, Timestamp: {tstext}",
      'color': 'warning',
      'title': title,
      'fields': fields,
      'ts': e['UTCTimestamp']
    }]
  }

def _slack_payload_u(event):
  e = event['event']
  link = 'https://falcon.crowdstrike.com/'
  title = "User Activity Audit Event"
  fields = [
    {
      "title": "OperationName",
      "value": e["OperationName"],
      "short": True
    },
    {
      "title": "UserId",
      "value": e["UserId"],
      "short": True
    }
  ]
  color = 'warning'
  for _e in e['AuditKeyValues']:
    if _e['Key'] == 'new_state':
      if _e['ValueString'] == 'ignored':
        color = INFORMATION_COLOR

    fields.append({
      "title": _e['Key'],
      "value": _e['ValueString'],
      "short": True
    })
  return {
    "attachments": [{
      "title": title,
      "title_link": link,
      "color": color,
      "fields": fields
    }]
  }

async def main(app_id, client_id, client_secret, offsetfile, webhook):
  def _notify_slack(event):
    meta = event['metadata']
    payload = None
    if meta['eventType'] == 'DetectionSummaryEvent':
      payload = _slack_payload_d(event)
    elif meta['eventType'] == 'AuthActivityAuditEvent':
      payload = _slack_payload_a(event)
    elif meta['eventType'] == 'UserActivityAuditEvent':
      payload = _slack_payload_u(event)
    if payload:
      requests.post(webhook, data=json.dumps(payload), headers={'Content-Type': 'application/json'})
  def _logger(event):
    logger.info(event)
  queue = asyncio.Queue()
  stream = EventStream(app_id)
  stream.set_credential(client_id, client_secret)
  notifier = _notify_slack if webhook else _logger

  offset = 0
  if offsetfile:
    with open(offsetfile, 'r') as f:
      offset = int(f.read().strip())

  await asyncio.gather(
    streaming(stream, queue, offset),
    consume(queue, offsetfile, notifier)
  )

async def streaming(eventstream, queue, offset):
  async for event in eventstream.retrieve_event(offset=offset):
    await queue.put(event)

async def consume(queue, offsetfile, notifier):
  f = None
  if offsetfile:
    f = open(offsetfile, 'r')
    offset = f.read().strip()
    f.close()

    f = open(offsetfile, 'w')
    f.seek(0)
    f.write(offset)
  while True:
    event = await queue.get()
    try:
      notifier(event)
      if f:
        meta = event['metadata']
        logger.debug('Write offset -> ' + str(meta['offset']))
        f.seek(0)
        f.write(str(meta['offset']))
    except:
      logger.error('Error occurred')
      logger.error(sys.exc_info())

if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  parser.add_argument("app_id", help="Identifier of a stream consumer")
  parser.add_argument("client_id", help="An identifier of a CrowdStrike API client.")
  parser.add_argument("client_secret", help="A client secret of a CrowdStrike API client.")
  parser.add_argument("--offset", help="/path/to/a-file-to-readwrite-an-offset")
  parser.add_argument("--webhook", help="slack incoming webhook url")
  parser.add_argument("-d", "--debug", action="store_true")
  parser.add_argument("--logfile", help="Path to log file.")
  args = parser.parse_args()

  default_handler = logging.handlers.RotatingFileHandler(args.logfile, maxBytes=10*1024*1024, backupCount=10) if args.logfile else logging.StreamHandler()
  handlers = [default_handler]
  if args.logfile and args.debug:
    handlers.append(logging.StreamHandler())
  logging.basicConfig(
    level=logging.DEBUG if args.debug else logging.INFO,
    format="%(asctime)s - %(name)s [%(levelname)s] : %(message)s",
    handlers=handlers
  )

  logger.debug(args.app_id)
  logger.debug(args.client_id)
  logger.debug(args.client_secret)
  logger.debug(args.offset)
  logger.debug(args.webhook)
  asyncio.run(main(args.app_id, args.client_id, args.client_secret, args.offset, args.webhook))
