from .apibase import OAuthBasedApi

class UserApi(OAuthBasedApi):
  METHOD = 'GET' # default
  PATH = '/users/entities/users/v1'

class UserByEmailApi(OAuthBasedApi):
  METHOD = 'GET'
  PATH = '/users/queries/user-uuids-by-email/v1'

class EmailsByCidApi(OAuthBasedApi):
  METHOD = 'GET'
  PATH = '/users/queries/emails-by-cid/v1'

class UserRolesByUidApi(OAuthBasedApi):
  METHOD = 'GET'
  PATH = '/user-roles/queries/user-role-ids-by-user-uuid/v1'

class UserRoleApi(OAuthBasedApi):
  METHOD = 'GET' # default
  PATH = '/user-roles/entities/user-roles/v1'
