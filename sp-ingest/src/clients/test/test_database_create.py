#!/usr/bin/env python3

from datetime import datetime, timedelta
import sys
sys.path.insert(1, '..')
from PGClient import PGClient

### Parameters
PG_HOST = "127.0.0.1"
PG_DB = "postgres"
PG_USER = "postgres"
PG_PASSWORD = "postgres"

# - Verbose output
verbose = True


def v_print(txt_to_output, txt_end='\n'):
    if verbose:
        print(txt_to_output, end=txt_end, flush=True)



if __name__ == '__main__':
    v_print('#### Database connect')
    pg_client = PGClient(PG_HOST, PG_DB, PG_USER, PG_PASSWORD)
    pg_client.pg_connect()
    pg_client.pg_version()

    v_print('')
    v_print('#### Database init')
    pg_client.pg_init()
    db_ok = pg_client.verify()
    if not db_ok:
        sys.exit(1)

    v_print('')
    v_print('#### Database close')
    pg_client.pg_close()

    sys.exit(0)
