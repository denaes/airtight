@csrf_exempt
def handle_payment(request):
    pass

class OrderView(View):
    @csrf_exempt
    def post(self, request):
        pass

@method_decorator(csrf_exempt, name='dispatch')
class ProfileUpdateView(View):
    pass

@method_decorator(csrf_exempt)
def webhook_handler(request):
    pass
