url = os.environ.get('API_URL')
requests.get(os.environ['METRICS_URL'])
token = os.environ.get('AUTH_TOKEN')
requests.post(url, json={'status': 'ok', 'env': os.environ.get('ENV')})
headers = {'Authorization': f'Bearer {os.environ.get("TOKEN")}'}
