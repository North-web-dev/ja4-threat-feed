import sys
import asyncio
import aiohttp

print(aiohttp.__version__, file=sys.stderr)


async def main():
    async with aiohttp.ClientSession() as s:
        async with s.get(sys.argv[1], timeout=aiohttp.ClientTimeout(total=20)) as r:
            sys.stdout.write(await r.text())


asyncio.run(main())
