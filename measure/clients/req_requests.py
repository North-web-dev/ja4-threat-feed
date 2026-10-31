import sys
import requests

print(requests.__version__, file=sys.stderr)
r = requests.get(sys.argv[1], timeout=20)
sys.stdout.write(r.text)
