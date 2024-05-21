from django.utils.decorators import decorator_from_middleware
from django.views.decorators.csrf import csrf_exempt


class DisableCSRFMiddleware:
    @csrf_exempt
    def __call__(self, get_response):
        self.get_response = get_response

        def middleware(request):
            return self.process_request(request)

        return middleware

    def process_request(self, request):
        return self.get_response(request)
