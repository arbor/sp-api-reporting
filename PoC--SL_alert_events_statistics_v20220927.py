#!/usr/bin/env python3

from datetime import datetime, timedelta
from sys import stderr
import requests
import urllib.parse
import logging

### Parameters
# - DB details
pg_host = "127.0.0.1"
pg_database = "sightline"
pg_user = "SLadmin"
pg_password = "SLadmin"

# - SL details ** PROVIDE DETAILS 
SL_LEADER = '172.18.11.115' # leader IP 
SL_APITOKEN = 'Mx1WpcC2daFGU0J7f1kW7FoCKz3R4K_Syfw81tW_' # REST API Token
#raise RuntimeError("SET SL Leader IP and API Token")

# - INIT Environment
#init_environment = False
init_environment = True
#raise RuntimeError("After the first successful run, comment 'init_environment = True' out")

def update_managed_obects_fetch():
	logging.info('#### Update Managed Objects fetch')
	MOs = get_managed_objects()
	pg_UPSERT_managed_objects(MOs)

def inital_alert_fetch():
	logging.info('#### Initial Alert fetch')
	
	alerts = get_alerts()
	pg_UPSERT_alerts(alerts)
	
	logging.info('## Updating alert last_update timestamp...', '')
	sql = '''UPDATE operational_info SET alert__last_update = %s WHERE ID = 1;'''
	cur = pg_conn.cursor()
	cur.execute(sql, [datetime.utcnow().isoformat()])
	pg_conn.commit()
	
	logging.info(' DONE', )

def update_alert_fetch(all_alerts=False):
	logging.info('#### Update Alert fetch')

	cur = pg_conn.cursor()
	
	if not all_alerts:
		sql = '''SELECT alert__last_update FROM operational_info WHERE ID = 1;'''
		cur.execute(sql)
		alert__last_update = cur.fetchall()[0][0]
		alert__last_update -= timedelta(minutes=60*2) # get alerts from last update TS - 2hours
		alerts = get_alerts(alert__last_update.isoformat())
	else:
		alerts = get_alerts(datetime(1970, 1, 1).isoformat())
	
	pg_UPSERT_alerts(alerts)
	logging.info('## Updating alert last_update timestamp...', '')
	sql = '''UPDATE operational_info SET alert__last_update = %s WHERE ID = 1;'''
	cur.execute(sql, [datetime.utcnow().isoformat()])
	pg_conn.commit()
	logging.info(' DONE', )

def ongoing_alert_fetch():
	logging.info('#### Ongoing Alert fetch')
	sql = '''SELECT id FROM alert WHERE ongoing = True;'''
	cur = pg_conn.cursor()
	cur.execute(sql)
	ongoing_alerts_rows = cur.fetchall()#[0][0]
	logging.info('## Alert count: {}'.format(len(ongoing_alerts_rows)))
	
	for alert_row in ongoing_alerts_rows:
		alert_id = alert_row[0]
		alerts = get_alerts(alert_id=alert_id)
		pg_UPSERT_alerts(alerts)


if __name__ == '__main__':
	logging.info('#### Database connect')
	pg_connect()
	
	if init_environment:
		logging.info('')
		logging.info('#### Database init')
		pg_init()
		
		logging.info('')
		inital_alert_fetch()

	logging.info('')
	update_managed_obects_fetch()
	
	logging.info('')
	update_alert_fetch()
	#update_alert_fetch(all_alerts=True) # to fetch all alerts each run
	
	logging.info('')
	ongoing_alert_fetch()

	logging.info('')
	logging.info('#### Database close')
	pg_close()
	
	
	
	
	