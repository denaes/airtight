# False positive cases for py/paramiko-missing-host-key-policy
import paramiko

def pass_cases():
    # Case 1: RejectPolicy (secure default behavior)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())

    # Case 2: WarningPolicy
    client.set_missing_host_key_policy(paramiko.WarningPolicy())

    # Case 3: Loading system host keys
    client.load_system_host_keys()

    # Case 4: Loading known hosts file
    client.load_host_keys("/home/user/.ssh/known_hosts")

    # Case 5: Custom strict policy
    class StrictPolicy(paramiko.MissingHostKeyPolicy):
        def missing_host_key(self, client, hostname, key):
            raise paramiko.SSHException(f"Unknown host: {hostname}")

    client.set_missing_host_key_policy(StrictPolicy())

    # Case 6: Comment referencing AutoAddPolicy
    # client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect("example.com")
