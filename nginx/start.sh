#!/bin/sh
# start.sh — launches nginx-agent in the background, then runs nginx in the
# foreground as PID 1.  When nginx exits (or receives SIGTERM from Docker),
# the container stops cleanly.
set -e

# Start nginx-agent in the background.
/usr/local/bin/nginx-agent &

# Hand control to nginx, which becomes the foreground process.
exec nginx -g "daemon off;"
