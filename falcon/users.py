from .apibase import OAuthBasedApi

class UserApi(OAuthBasedApi):
  METHOD = 'GET' # default
  PATH = '/users/entities/users/v1'

  def get(self, ids):
    res = super().get(ids=ids)
    if res.status_code == 404:
      logger.warning(f'no such user: {ids}')
      return []
    elif res.status_code != 200:
      logger.error(f'error: {res.status_code}, {res.json()["errors"][0]["message"]}')
      raise RuntimeError()
    return res.json()['resources']

class UserByEmailApi(OAuthBasedApi):
  METHOD = 'GET'
  PATH = '/users/queries/user-uuids-by-email/v1'

  def get(self, uid):
    res = super().get(uid=uid)
    if res.status_code == 404:
      logger.warning(f'no such user: {uid}')
      return []
    elif res.status_code != 200:
      logger.error(f'error: {res.status_code}, {res.json()["errors"][0]["message"]}')
      raise RuntimeError()
    return res.json()['resources']

class EmailsByCidApi(OAuthBasedApi):
  METHOD = 'GET'
  PATH = '/users/queries/emails-by-cid/v1'

class UserRolesByUidApi(OAuthBasedApi):
  METHOD = 'GET'
  PATH = '/user-roles/queries/user-role-ids-by-user-uuid/v1'

  def get(self, user_uuid):
    res = super().get(user_uuid=user_uuid)
    if res.status_code != 200:
      logger.error(f'error: {res.status_code}, {res.json()["errors"][0]["message"]}')
      raise RuntimeError()
    return res.json()['resources']

class UserRoleApi(OAuthBasedApi):
  METHOD = 'GET' # default
  PATH = '/user-roles/entities/user-roles/v1'
