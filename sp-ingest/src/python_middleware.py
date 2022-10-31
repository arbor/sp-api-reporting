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

    def db_connect(self):
        ''' Connect to the Postgres database.  Return true if tables needed to be created. '''
        logging.info('#### Database connect')
        self.pg_conn = self.pg_client.pg_connect()
        tables_exist = self.pg_client.are_tables_and_views_created()
        if not tables_exist:
            logging.info('Create and initialize database tables')
            self.pg_client.pg_init()
            return True
        return False

    def db_disconnect(self):
        logging.info('#### Database close')
        self.pg_client.pg_close()
        
    def update_managed_obects_fetch(self):
        logging.info('')
        logging.info('#### Update Managed Objects fetch')
        MOs = self.sp_client.get_managed_objects()
        self.pg_client.pg_UPSERT_managed_objects(MOs)
        self.pg_client.update_timestamp_managed_object()

    def did_initial_fetch(self):
        logging.info('#### Did we do initial fetch?')
        alert_ts = self.pg_client.fetch_timestamp_alert()
        mo_ts = self.pg_client.fetch_timestamp_managed_object()
        rval = True
        if not alert_ts or not mo_ts or alert_ts.year == 1970 or mo_ts.year == 1970:
            rval = False
        logging.info(f'  Initial fetch done: {rval}')
        return rval

    def initial_alert_fetch(self):
        logging.info('')
        logging.info('#### Initial Alert fetch')

        # First, get alerts from sightline
        logging.info(f'   Initial days of alerts to fetch: {self.initial_days}')
        end_ts = datetime.utcnow()
        start_ts = end_ts - timedelta(days=self.initial_days)
        alerts = self.sp_client.get_alerts(start_time=start_ts)

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
        alerts = self.sp_client.get_alerts(start_time=start_ts)

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
    parser = argparse.ArgumentParser(description='Script to populate and keep updating postgres docker container.  No arguments required, as it detects what initialization is needed.')
    pars = parser.parse_args()

    # Initial setup
    middleware = PythonMiddleware()
    clean_new_db = middleware.db_connect()
    need_initial_fetch = not middleware.did_initial_fetch()
    if clean_new_db or need_initial_fetch:
        middleware.initial_alert_fetch()
        middleware.update_managed_obects_fetch()

    # Subsequent updates
    sleep_period_secs = SECONDS_PER_MINUTE*middleware.get_update_minutes()
    while True:
        logging.info(f'## Sleeping for {sleep_period_secs} seconds')
        time.sleep(sleep_period_secs)

        logging.info(f'###### Periodic update, time now is {datetime.utcnow()}')
        middleware.update_managed_obects_fetch()
        middleware.update_alert_fetch()
        middleware.ongoing_alert_fetch()

    # If we get here!, disconnect
    middleware.db_disconnect()
