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
PG_HOST     = "postgres"
PG_DB       = "postgres"
PG_USER     = "postgres"
PG_PASSWORD = "postgres"

# - SL details ** PROVIDE DETAILS
load_dotenv()
SL_LEADER = os.environ.get('SL_LEADER') # leader IP 
SL_APITOKEN = os.environ.get('SL_APITOKEN') # REST API Token

class PythonMiddleware():

    def __init__(self):
        self.pg_client = PGClient(PG_HOST, PG_DB, PG_USER, PG_PASSWORD)
        self.sp_client = SPClient(SL_LEADER, SL_APITOKEN)

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

        alerts = self.sp_client.get_alerts()
        self.pg_client.pg_UPSERT_alerts(alerts)

        logging.info('## Updating alert last_update timestamp...', '')
        sql = '''UPDATE operational_info SET alert__last_update = %s WHERE ID = 1;'''
        cur = self.pg_conn.cursor()
        cur.execute(sql, [datetime.utcnow().isoformat()])
        self.pg_conn.commit()

        logging.info(' DONE', )

    def update_alert_fetch(self, all_alerts=False):
        logging.info('#### Update Alert fetch')

        cur = self.pg_conn.cursor()

        if not all_alerts:
            sql = '''SELECT alert__last_update FROM operational_info WHERE ID = 1;'''
            cur.execute(sql)
            alert__last_update = cur.fetchall()[0][0]
            # get alerts from last update TS - 2hours
            alert__last_update -= timedelta(minutes=60*2)
            alerts = self.sp_client.get_alerts(alert__last_update.isoformat())
        else:
            alerts = self.sp_client.get_alerts(datetime(1970, 1, 1).isoformat())

        self.pg_client.pg_UPSERT_alerts(alerts)
        logging.info('## Updating alert last_update timestamp...', '')
        sql = '''UPDATE operational_info SET alert__last_update = %s WHERE ID = 1;'''
        cur.execute(sql, [datetime.utcnow().isoformat()])
        self.pg_conn.commit()
        logging.info(' DONE', )

    def ongoing_alert_fetch(self):
        logging.info('#### Ongoing Alert fetch')
        sql = '''SELECT id FROM alert WHERE ongoing = True;'''
        cur = self.pg_conn.cursor()
        cur.execute(sql)
        ongoing_alerts_rows = cur.fetchall()  # [0][0]
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
