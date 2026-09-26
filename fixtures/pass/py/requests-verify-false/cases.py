requests.get(url, verify=True)
requests.get(url, verify="/etc/ssl/internal-ca.pem")
session.post(url, json=body)
ctx = ssl.create_default_context()
verify_signature = False
should_verify = False if debug else True
