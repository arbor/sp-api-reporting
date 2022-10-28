#!/usr/bin/env python3

from datetime import datetime, timedelta
from clients.PGClient import PGClient
from clients.SPClient import SPClient

import argparse
import logging
logging.basicConfig(level=logging.INFO)
import os
import time
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# File constants
MINUTES_PER_DAY = 1440
SECONDS_PER_MINUTE = 60

class PythonMiddleware():

    # Class constants
    DEFAULT_SL_INITIAL_ALERT_FETCH_DAYS = 30
    DEFAULT_SL_UPDATE_ALERT_FETCH_MINUTES = MINUTES_PER_DAY

    def __init__(self):
        pg_host = os.environ.get('POSTGRES_HOST')
        pg_db = os.environ.get('POSTGRES_DB')
        pg_user = os.environ.get('POSTGRES_USER')
        pg_password = os.environ.get('POSTGRES_PASSWORD')
        logging.info(f'   Connection details for postgres: <{pg_host},{pg_db},{pg_user},********>')
        self.pg_client = PGClient(pg_host, pg_db, pg_user, pg_password)

        logging.info('#### Sightline setup')
        sl_leader = os.environ.get('SL_LEADER')
        sl_token = os.environ.get('SL_APITOKEN')
        logging.info(f'   Connection to Sightline: SL_LEADER of {sl_leader}')
        self.sp_client = SPClient(sl_leader, sl_token)

        s_initial_days = os.environ.get('SL_INITIAL_ALERT_DAYS')
        s_update_minutes = os.environ.get('SL_UPDATE_ALERT_MINUTES')
        if s_initial_days and s_initial_days.isnumeric():
            self.initial_days = int(s_initial_days)
        else:
            self.initial_days = self.DEFAULT_SL_INITIAL_ALERT_FETCH_DAYS
        if s_update_minutes and s_update_minutes.isnumeric():
            self.update_minutes = int(s_update_minutes)
        else:
            self.update_minutes = self.DEFAULT_SL_UPDATE_ALERT_FETCH_DAYS

    def get_update_minutes(self):
        return self.update_minutes

    def db_connect(self, setup):
        logging.info('#### Database connect')
        self.pg_conn = self.pg_client.pg_connect()
        if setup:
            logging.info('Create and initialize database tables')
            self.pg_client.pg_init()
            
    def db_disconnect(self):
        logging.info('#### Database close')
        self.pg_client.pg_close()
        
    def update_managed_obects_fetch(self):
        logging.info('')
        logging.info('#### Update Managed Objects fetch')
        MOs = self.sp_client.get_managed_objects()
        self.pg_client.pg_UPSERT_managed_objects(MOs)
        self.pg_client.update_timestamp_managed_object()

    def initial_alert_fetch(self):
        logging.info('')
        logging.info('#### Initial Alert fetch')

        # First, get alerts from sightline
        logging.info(f'   Initial days of alerts to fetch: {self.initial_days}')
        end_ts = datetime.utcnow()
        start_ts = end_ts - timedelta(days=self.initial_days)
        alerts = self.sp_client.get_alerts(start_time=start_ts, stop_time=end_ts)

        # Then, write these alerts to postgres
        self.pg_client.pg_UPSERT_alerts(alerts)
        self.pg_client.update_timestamp_alert(update_time=end_ts)

    def update_alert_fetch(self):
        logging.info('')
        logging.info('#### Update Alert fetch')

        # First, get alerts from sightline
        start_ts = self.pg_client.fetch_timestamp_alert()
        end_ts = datetime.utcnow()
        update_timedelta = end_ts - start_ts
        if update_timedelta > timedelta(minutes=self.update_minutes):
            logging.info(f'   Update alerts, minutes of alerts to fetch: {self.update_minutes}')
            start_ts = end_ts - timedelta(minutes=self.update_minutes)
        alerts = self.sp_client.get_alerts(start_time=start_ts, stop_time=end_ts)

        # Then, write these alerts to postgres
        self.pg_client.pg_UPSERT_alerts(alerts)
        self.pg_client.update_timestamp_alert(update_time=end_ts)

    def ongoing_alert_fetch(self):
        logging.info('')
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

    # Initial setup
    middleware = PythonMiddleware()
    middleware.db_connect(init_environment)
    if init_environment:
        middleware.initial_alert_fetch()
        middleware.update_managed_obects_fetch()

    # Subsequent updates
    sleep_period_secs = SECONDS_PER_MINUTE*middleware.get_update_minutes()/2
    while True:
        logging.info(f'## Sleeping for {sleep_period_secs} seconds')
        time.sleep(sleep_period_secs)

        logging.info(f'###### Periodic update, time now is {datetime.utcnow()}')
        middleware.update_managed_obects_fetch()
        middleware.update_alert_fetch()
        middleware.ongoing_alert_fetch()

    # If we get here!, disconnect
    middleware.db_disconnect()
