from django.core.handlers import base
from django.core.handlers._handlers import (
    WSGIRequest, call_wsgi_handler, get_path_info, get_script_name, LimitedStream)


class WSGIHandler(base.BaseHandler):
    request_class = WSGIRequest

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.load_middleware()

    def __call__(self, environ, start_response):
        return call_wsgi_handler(self, environ, start_response)

