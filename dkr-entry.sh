#!/bin/sh

set -e

wait_for_vault() {
  echo Waiting for Vault
  while ! (telnet $VAULT_ADDR 8200 > /dev/null 2>&1); do
    echo -n .
    sleep 1
  done
  echo
}

if [ "$1" = "start" ]
then
  echo Initializing
  wait_for_vault
  echo Starting
  vault
fi

exec "$@"