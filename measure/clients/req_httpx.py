import sys
import httpx

print(httpx.__version__, file=sys.stderr)
http2 = len(sys.argv) > 2 and sys.argv[2] == "--http2"
with httpx.Client(http2=http2, timeout=20) as c:
    r = c.get(sys.argv[1])
    sys.stdout.write(r.text)
