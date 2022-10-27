#!/usr/bin/env python3

from datetime import datetime, timedelta
from clients.PGClient import PGClient
from clients.SPClient import SPClient

import argparse
import logging
logging.basicConfig(level=logging.INFO)
import os
from dotenv import load_dotenv

# Parameters
# - DB details
PG_HOST     = 'postgres'
PG_DB       = 'postgres'
PG_USER     = 'postgres'
PG_PASSWORD = 'postgres'

# Load environment variables
load_dotenv()

def get_env_value(base_var: str, default_value: str = ''):
    dev_var = 'DEV' + base_var
    value = os.environ.get(dev_var)
    if value:
        return value
    value = os.environ.get(base_var)
    if value:
        return value
    return default_value


class PythonMiddleware():

    def __init__(self):
        pg_host = get_env_value('POSTGRES_HOST', 'postgres')
        pg_db = get_env_value('POSTGRES_DB', 'postgres')
        pg_user = get_env_value('POSTGRES_USER', 'postgres')
        pg_password = get_env_value('POSTGRES_PASSWORD', 'postgres')
        self.pg_client = PGClient(pg_host, pg_db, pg_user, pg_password)

        sl_leader = get_env_value('SL_LEADER')
        sl_token = get_env_value('SL_APITOKEN')
        self.sp_client = SPClient(sl_leader, sl_token)

    def connect(self, setup):
        self.pg_conn = self.pg_client.pg_connect()
        if setup:
            logging.info('Database init')
            self.pg_client.pg_init()
            middleware.inital_alert_fetch()
            
    def disconnect(self):
        self.pg_client.pg_close()
        
    def update_managed_obects_fetch(self):
        logging.info('#### Update Managed Objects fetch')
        MOs = self.sp_client.get_managed_objects()
        self.pg_client.pg_UPSERT_managed_objects(MOs)

    def inital_alert_fetch(self):
        logging.info('#### Initial Alert fetch')

        # First, get alerts from sightline
        alerts = self.sp_client.get_alerts()

        # Then, write these alerts to postgres
        self.pg_client.pg_UPSERT_alerts(alerts)
        self.pg_client.update_timestamp_alert()

    def update_alert_fetch(self, all_alerts=False):
        logging.info('#### Update Alert fetch')

        # First, get alerts from sightline
        if not all_alerts:
            alert__last_update = self.pg_client.fetch_timestamp_alert()
            alert__last_update -= timedelta(minutes=60*2)
            alerts = self.sp_client.get_alerts(alert__last_update.isoformat())
        else:
            alerts = self.sp_client.get_alerts(datetime(1970, 1, 1).isoformat())

        # Then, write these alerts to postgres
        self.pg_client.pg_UPSERT_alerts(alerts)
        self.pg_client.update_timestamp_alert()

    def ongoing_alert_fetch(self):
        logging.info('#### Ongoing Alert fetch')
        ongoing_alerts_rows = self.pg_client.get_ongoing_alerts()
        logging.info('## Alert count: {}'.format(len(ongoing_alerts_rows)))

        for alert_row in ongoing_alerts_rows:
            alert_id = alert_row[0]
            alerts = self.sp_client.get_alerts(alert_id=alert_id)
            self.pg_client.pg_UPSERT_alerts(alerts)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Taking Input on Script')
    parser.add_argument('--setup', dest='setup', type=bool, default=False, 
                        help='Setup the Database for SP Data')
    parser.add_argument('-pg_host', dest='pg_host', type=bool, default=False, 
                        help='Setup the Database for SP Data')
    pars = parser.parse_args()
    init_environment = pars.setup
    
    logging.info('#### Database connect')
    middleware = PythonMiddleware()

    middleware.connect(setup=init_environment)
    logging.info('')
    middleware.update_managed_obects_fetch()

    logging.info('')
    middleware.update_alert_fetch()
    # update_alert_fetch(all_alerts=True) # to fetch all alerts each run

    logging.info('')
    middleware.ongoing_alert_fetch()

    logging.info('')
    logging.info('#### Database close')
    middleware.disconnect
