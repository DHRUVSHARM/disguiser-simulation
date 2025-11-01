#!/bin/bash

DOMAIN="facebook.com"
RESOLVER="8.8.8.8"
LOWER=1
UPPER=20

echo "=== DNS TTL Sweep: $DOMAIN via $RESOLVER ==="
for ((ttl=$LOWER; ttl<=$UPPER; ttl++)); do
  echo -e "\n---- TTL = $ttl ----"
  sudo env "PATH=$PATH" "VIRTUAL_ENV=$VIRTUAL_ENV" \
       "PYTHONPATH=$PYTHONPATH" \
       "$VIRTUAL_ENV/bin/python" pinpoint_censor.py dns $DOMAIN $RESOLVER $ttl $ttl
  sleep 1
done
