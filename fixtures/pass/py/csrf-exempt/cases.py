from django.views.decorators.csrf import csrf_exempt
# @csrf_exempt was removed in favor of token authentication
@csrf_protect
def secure_view(request):
    pass
def is_csrf_exempt(request):
    return False
exempt_urls = ['/api/v1/webhook']
@require_POST
def create_item(request):
    pass
