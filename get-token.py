#!/bin/env python3

import datetime
import json
import secrets
import time

from dateutil.relativedelta import relativedelta

# Simulate network delay, sleep for 2 seconds
time.sleep(2)

# Simulate token expiration time in 10 minutes
now = datetime.datetime.utcnow()
expiration_time = now + relativedelta(minutes=+10)

data = {
    "kind": "ExecCredential",
    "apiVersion": "client.authentication.k8s.io/v1beta1",
    "status": {
        "expirationTimestamp": expiration_time.strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),  # format datetime as ISO 8601 string
        "token": secrets.token_urlsafe(32),
    },
}

print(json.dumps(data))
