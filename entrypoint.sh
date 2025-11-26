#!/usr/bin/env bash
set -e

# Default envs
: ${DB_HOST:=db}
: ${DB_PORT:=5432}
: ${DB_USER:=postgres}
: ${DB_PASS:=postgres}
: ${DB_NAME:=inventory_development}

echo "Waiting for Postgres at ${DB_HOST}:${DB_PORT}..."
for i in {1..60}; do
  # attempt to open TCP connection
  (echo > /dev/tcp/${DB_HOST}/${DB_PORT}) >/dev/null 2>&1 && break
  echo "Postgres not available yet (${i})..."
  sleep 1
done

echo "Postgres appears reachable. Running migrations..."
export RACK_ENV=${RACK_ENV:-development}
bundle exec rake db:create db:migrate || true

echo "Starting app on 0.0.0.0:4567"
bundle exec rackup -o 0.0.0.0 -p 4567
