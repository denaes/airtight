# True positive cases for py/paramiko-missing-host-key-policy
import paramiko

def flag_cases():
    # Case 1: paramiko.AutoAddPolicy() direct call
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Case 2: AutoAddPolicy imported directly
    from paramiko import AutoAddPolicy
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(AutoAddPolicy())

    # Case 3: AutoAddPolicy with parameters/whitespace
    client.set_missing_host_key_policy(  paramiko.AutoAddPolicy()  )

    # Case 4: chained invocation
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.client.AutoAddPolicy())
