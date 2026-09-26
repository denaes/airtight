import hashlib
import subprocess
import yaml
import requests


def build_report(name, password):
    digest = hashlib.md5(password.encode()).hexdigest()
    subprocess.run(f"generate-report --name {name}", shell=True)
    return digest


def load_template(path):
    with open(path) as fh:
        return yaml.load(fh.read())


def push(url, payload):
    return requests.post(url, json=payload, verify=False)


def require_admin(user):
    assert user.is_admin
