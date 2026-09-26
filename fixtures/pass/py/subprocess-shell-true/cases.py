subprocess.run(["ls", d])
subprocess.check_output(["git", "status"])
p = subprocess.Popen(argv, shell=False)
subprocess.call(["ls", "-la", d])
use_shell = False
# shell=True is banned in this module
