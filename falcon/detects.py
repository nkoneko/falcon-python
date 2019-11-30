from .apibase import OAuthBasedApi

class DetectsQueryApi(OAuthBasedApi):
  METHOD = 'GET'
  PATH = '/detects/queries/detects/v1'

  def __call__(self, **kwargs):
    res = super().__call__(**kwargs)
    self.res = res
    self.params = kwargs
    return res.json()['resources']

  def has_next(self):
    if hasattr(self, 'res'):
      if self.res.status_code == 200:
        meta = self.res.json()['meta']
        p= meta['pagination']
        return p['offset'] + p['limit'] < p['total']
    return False

  def fetch_next(self):
    meta = self.res.json()['meta']
    p = meta['pagination']
    offset = p['offset'] + p['limit']
    has_offset_param = 'offset' in self.params.keys()
    self.params['offset'] = offset
    res = self.__call__(**self.params)
    if not has_offset_param:
      del self.params['offset']
    return res

class DetectsSummaryApi(OAuthBasedApi):
  METHOD = 'POST'
  PATH = '/detects/entities/summaries/GET/v1'

  def __call__(self, *args, **kwargs):
    if len(args):
      res = super().__call__(ids=args)
    else:
      res = super().__call__(**kwargs)
    return res.json()['resources']

class DetectsUpdateApi(OAuthBasedApi):
  METHOD = 'PATCH'
  PATH = '/detects/entities/detects/v1'

