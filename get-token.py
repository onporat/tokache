#!/usr/bin/env python3

import json
import secrets
import time


# Simulate network delay, sleep for 2 seconds
time.sleep(2)

# Simulate token expiration time in 10 minutes
expiration_time = time.gmtime(int(time.time()) + 600)

data = {
    "kind": "ExecCredential",
    "apiVersion": "client.authentication.k8s.io/v1beta1",
    "status": {
        "expirationTimestamp": time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", expiration_time
        ),  # format datetime as ISO 8601 string
        "token": secrets.token_urlsafe(32),
    },
}

print(json.dumps(data))
