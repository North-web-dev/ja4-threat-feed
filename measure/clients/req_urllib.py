import sys
import platform
import urllib.request

print(platform.python_version(), file=sys.stderr)
with urllib.request.urlopen(sys.argv[1], timeout=20) as r:
    sys.stdout.buffer.write(r.read())
