subprocess.run(["rm", "-rf", path])
os.system("systemctl daemon-reload")
subprocess.run(["ping", "-c", "1", host])
os.popen("uptime").read()
cmd = f"rm -rf {path}"  # logged, never executed
subprocess.run(["convert", name])
