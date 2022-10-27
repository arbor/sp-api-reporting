#!/usr/bin/env python3

from datetime import datetime, timedelta
import os
import sys
sys.path.insert(1, '..')
from PGClient import PGClient

### Parameters
PG_HOST_OUTSIDE = '127.0.0.1'
PG_HOST_IN_DOCKER = 'postgres'
PG_DB = 'postgres'
PG_USER = 'postgres'
PG_PASSWORD = 'postgres'

# - Verbose output
verbose = True

def is_docker():
    path = '/proc/self/cgroup'
    return (
        os.path.exists('/.dockerenv') or
        os.path.isfile(path) and any('docker' in line for line in open(path))
    )

def v_print(txt_to_output, txt_end='\n'):
    if verbose:
        print(txt_to_output, end=txt_end, flush=True)



if __name__ == '__main__':
    v_print('#### Database connect...', '')
    host = PG_HOST_OUTSIDE
    if is_docker():
        host = PG_HOST_DOCKER
    pg_client = PGClient(host, PG_DB, PG_USER, PG_PASSWORD)
    if not pg_client.pg_connect():
        v_print('FAIL')
        sys.exit(1)
    v_print('DONE')
    pg_client.pg_version()

    v_print('')
    v_print('#### Database init...', '')
    pg_client.pg_init()
    v_print('DONE')

    v_print('')
    v_print('#### Verify database after init...', '')
    db_ok = pg_client.verify()
    if not db_ok:
        v_print('FAIL')
        sys.exit(1)
    v_print('DONE')

    v_print('#### Verify database timestamp ops...', '')
    pg_client.update_timestamp_managed_object()
    pg_client.update_timestamp_alert()
    now = datetime.utcnow()
    alert_timestamp = pg_client.fetch_timestamp_alert()
    mo_timestamp = pg_client.fetch_timestamp_managed_object()
    alert_delta = now - alert_timestamp
    if not alert_delta.total_seconds() < 1:
        v_print('FAIL')
        sys.exit(1)
    mo_delta = now - mo_timestamp
    if not mo_delta.total_seconds() < 1:
        v_print('FAIL')
        sys.exit(1)
    v_print('DONE')

    v_print('')
    v_print('#### Database close...', '')
    pg_client.pg_close()
    v_print('DONE')

    sys.exit(0)
