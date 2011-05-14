class BasicAuthMiddleware(object):

    def __init__(self, app, username, password, realm='protected'):
        """Initializes the middleware."""
        self.app = app
        self.username = username
        self.password = password
        self.realm = realm

    def __call__(self, environ, start_response):
        """Handles the http request."""
        auth = environ.get('HTTP_AUTHORIZATION')
        if auth:
            #Authentication provided, check it
            scheme, credentials = auth.split(None, 1)
            username, password = credentials.decode('base64').split(':', 1)
            if username == self.username and password == self.password:
                #Authentication valid. Return as normal
                return self.app(environ, start_response)
        #No authentication provided. Return 401.
        app_iter = self.app(environ, self._401_callback(start_response))
        return ['Please authenticate',]

    def _401_callback(self, start_response):
        """Turns a response into a 401 response"""
        def callback(status, headers, exc_info=None):
            status='401 Unauthorized'
            headers.append(('WWW-Authenticate','Basic realm="%s"' % self.realm))
            start_response(status, headers, exc_info)
        return callback
