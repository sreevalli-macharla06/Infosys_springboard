import urllib.request
import json
import time

time.sleep(2)

def test_filter(qs):
    req = urllib.request.Request(f'http://127.0.0.1:8000/predictions?{qs}')
    with urllib.request.urlopen(req) as response:
        data = json.loads(response.read().decode())
        print(f'{qs}: Total={data.get("total")}, Items={len(data.get("items", []))}')

test_filter('severity=Low&limit=2')
test_filter('severity=High&limit=2')
test_filter('verdict=Normal&limit=2')
test_filter('verdict=Suspicious&severity=Medium&limit=2')
test_filter('verdict=All&limit=2')
