#!/usr/bin/env python3

#v20221013

from datetime import datetime, timedelta
import requests
import urllib.parse
import os
from dotenv import load_dotenv

import psycopg2


### DB details
# user: SLadmin / pw: SLadmin
# Database: sightline / owner: SLadmin


### Parameters
# - DB details
pg_host = "172.23.0.2"
pg_database = "postgres"
pg_user = "postgres"
pg_password = "postgres"

# - SL details ** PROVIDE DETAILS 
load_dotenv()
SL_LEADER = os.environ.get('SL_LEADER') # leader IP 
SL_APITOKEN = os.environ.get('SL_APITOKEN') # REST API Token
# raise RuntimeError("SET SL Leader IP and API Token")

# - INIT Environment
init_environment = False 
init_environment = True
# raise RuntimeError("After the first successful run, comment 'init_environment = True' out")


# - CERT handling
CERT_verify = False # False or cert file
if CERT_verify == False:
	import urllib3
	urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# - Results per Page
perPage = "perPage=50" # default: "perPage=50"

# - Verbose output
verbose = True

### PostgreSQL handler
pg_conn = None 


def v_print(txt_to_output, txt_end='\n'):
	if verbose:
		print(txt_to_output, end=txt_end, flush=True)



def pg_connect():
	global pg_conn
	try:
		v_print('## Connecting to database...', '')

		v_print(pg_host)
		
		pg_conn = psycopg2.connect(
			host=pg_host,
			database=pg_database,
			user=pg_user,
			password=pg_password)
		
		v_print(' DONE')
	except (Exception, psycopg2.DatabaseError) as error:
		print(error)
		print('!! ERROR: Can not connect to database -> EXIT')
		exit(1)



def pg_close():
	global pg_conn
	
	try:
		if pg_conn is not None:
			v_print('## Closing database...', '')
			pg_conn.close()
			v_print(' DONE')
			
		else:
			print('!! ERROR: No database connection to close')
	except (Exception, psycopg2.DatabaseError) as error:
		print(error)



def pg_version():
	global pg_conn
	
	if pg_conn is not None:
		v_print('## PostgreSQL database version: ')
		
		cur = pg_conn.cursor()
		cur.execute('SELECT version();')
	
		db_version = cur.fetchone()
		
		v_print(db_version)
	else:
		print('!! ERROR: No database connection')
	


def pg_init():
	global pg_conn
	v_print('## Creating database table and views ...', '')
			
	sqls = ['''
	/* !!! DROP VIEWs !!!*/
	
	/* v_operational_info */
	DROP VIEW IF EXISTS v_operational_info;
	
	/* v_alert_types__of_alerts */
	DROP VIEW IF EXISTS v_alert_types__of_alerts;
	
	/* v_directions__of_alerts */
	DROP VIEW IF EXISTS v_directions__of_alerts;
	
	/* v_managed_object_names__of_alerts */
	DROP VIEW IF EXISTS v_managed_object_names__of_alerts;
	
	/* v_security_levels__of_alerts */
	DROP VIEW IF EXISTS v_security_levels__of_alerts;

	/* v_mitigation_subtypes__of_alerts */
	DROP VIEW IF EXISTS v_mitigation_subtypes__of_alerts;

	/* v_alert */
	DROP VIEW IF EXISTS v_alert;

	/* v_alert_mitigations */
	DROP VIEW IF EXISTS v_alert_mitigations;
	
	/* !!! DROP TABLES !!!*/
	/* operational_info */
	/* ---- */ DROP TABLE IF EXISTS operational_info; /* */

	/* mapper_managed_object */
	/* ---- */ DROP TABLE IF EXISTS mapper_managed_object; /* */
	
	/* mapper_alert_type */
	DROP TABLE IF EXISTS mapper_alert_type;
	
	/* mapper_alert_importance */
	DROP TABLE IF EXISTS mapper_alert_importance;

	/* mapper_mitigation_subtype */
	DROP TABLE IF EXISTS mapper_mitigation_subtype;
	
	/* alert_mitigations */
	/* ---- */ DROP TABLE IF EXISTS alert_mitigations; /* */
	
	/* alert */
	/* ---- */ DROP TABLE IF EXISTS alert; /* */
	
	/* !!! CREATE TABLES !!!*/

	/* alert */
	CREATE TABLE IF NOT EXISTS alert (
		id integer NOT NULL PRIMARY KEY,
		alert_class text,
		alert_type text,
		classification text,
		importance smallint,
		ongoing boolean,
		start_time timestamp without time zone,
		stop_time timestamp without time zone,
		countries text[],
		direction text,
		fast_detected boolean DEFAULT false,
		host_address inet,
		impact_boundary text,
		impact_bps double precision,
		impact_pps double precision,
		ip_version smallint,
		misuse_types text[],
		protocols text[],
		severity_percent double precision,
		severity_threshold double precision,
		severity_unit text,
		managed_object_id integer,
		last_updated timestamp without time zone
		);

	/* alert_mitigations */
	CREATE TABLE IF NOT EXISTS alert_mitigations (
		id text NOT NULL PRIMARY KEY,
		mitigation_id text,
		alert_id integer,
		name text,
		subtype text,
		is_automitigation boolean,
		user_name text,
		ongoing boolean,
		start timestamp without time zone,
		stop timestamp without time zone,
		r_drop_bps_avg double precision,
		r_drop_bps_max double precision,
		r_drop_bps_sum double precision,
		r_drop_bps_timeseries double precision[],
		r_drop_bps_timeseries_start timestamp without time zone,
		r_drop_bps_step integer,
		r_drop_pps_avg double precision,
		r_drop_pps_max double precision,
		r_drop_pps_sum double precision,
		r_drop_pps_timeseries double precision[],
		r_drop_pps_timeseries_start timestamp without time zone,
		r_drop_pps_step integer,
		last_updated timestamp without time zone);

	/* alert_mitigations */
	CREATE TABLE mapper_alert_importance (
		id smallint NOT NULL PRIMARY KEY,
		importance_txt character varying(6));
	INSERT INTO mapper_alert_importance VALUES (0, 'Low');
	INSERT INTO mapper_alert_importance VALUES (2, 'High');
	INSERT INTO mapper_alert_importance VALUES (1, 'Medium');
	
	/* alert_mitigations */
	CREATE TABLE mapper_alert_type (
		id character varying(30) NOT NULL PRIMARY KEY,
		alert_type_txt character varying(30));
	INSERT INTO mapper_alert_type VALUES ('dos_host_detection', 'Host Detection');
	INSERT INTO mapper_alert_type VALUES ('dos_profiled_router', 'Profiled Router');
	INSERT INTO mapper_alert_type VALUES ('dos_profiled_network', 'Profiled Network');
	
	/* mapper_mitigation_subtype */
	CREATE TABLE mapper_mitigation_subtype (
		subtype character varying(15) NOT NULL PRIMARY KEY,
		subtype_txt text NOT NULL);
	INSERT INTO mapper_mitigation_subtype VALUES ('tms', 'TMS');
	INSERT INTO mapper_mitigation_subtype VALUES ('flowspec', 'FlowSpec');
	INSERT INTO mapper_mitigation_subtype VALUES ('blackhole', 'Blackhole');


	/* mapper_managed_object */
	CREATE TABLE IF NOT EXISTS mapper_managed_object (
				id integer NOT NULL PRIMARY KEY,
				managed_object_name text,
				last_updated timestamp without time zone
				);
	INSERT INTO mapper_managed_object VALUES (1, 'Profiled all', '1970-01-01 00:00:00') ON CONFLICT (id) DO NOTHING;
	INSERT INTO mapper_managed_object VALUES (10, 'Dark IP', '1970-01-01 00:00:00') ON CONFLICT (id) DO NOTHING;
	INSERT INTO mapper_managed_object VALUES (11, 'Multicast', '1970-01-01 00:00:00') ON CONFLICT (id) DO NOTHING;
	INSERT INTO mapper_managed_object VALUES (27, 'Internet', '1970-01-01 00:00:00') ON CONFLICT (id) DO NOTHING;
	INSERT INTO mapper_managed_object VALUES (28, 'All Subscribers', '1970-01-01 00:00:00') ON CONFLICT (id) DO NOTHING;
	INSERT INTO mapper_managed_object VALUES (71, 'Global Detection', '1970-01-01 00:00:00') ON CONFLICT (id) DO NOTHING;
		
	/* operational_info */
	CREATE TABLE IF NOT EXISTS operational_info (
		id serial NOT NULL PRIMARY KEY,
		alert__last_update timestamp without time zone,
		managed_object__last_update timestamp without time zone,
		tables_revision smallint
		);
	
	INSERT INTO operational_info (id, alert__last_update, managed_object__last_update, tables_revision) VALUES (1, '1970-01-01 02:00:00', '1970-01-01 02:00:00', 2) ON CONFLICT (id) DO NOTHING;
	''',
	'''
	/* !!! CREATE VIEWs !!!*/

	/* v_alert_mitigations */
	CREATE OR REPLACE VIEW v_alert_mitigations
		AS
		SELECT alert_mitigations.id,
			alert_mitigations.mitigation_id,
			alert_mitigations.alert_id,
			alert_mitigations.name,
			alert_mitigations.subtype,
			mapper_mitigation_subtype.subtype_txt,
			alert_mitigations.is_automitigation,
			alert_mitigations.user_name,
			alert_mitigations.ongoing,
			alert_mitigations.start,
			alert_mitigations.stop,
			(alert_mitigations.r_drop_bps_sum /8)::bigint as r_drop_bytes,
			alert_mitigations.r_drop_pps_sum as r_drop_packets,
			alert_mitigations.r_drop_bps_max,
			alert_mitigations.r_drop_pps_max,
			alert_mitigations.last_updated
			FROM alert_mitigations
			JOIN mapper_mitigation_subtype ON alert_mitigations.subtype = mapper_mitigation_subtype.subtype::text;
	
	/* v_alert */
	CREATE OR REPLACE VIEW v_alert
		AS
		SELECT alert.id,
			alert.alert_class,
			alert.alert_type,
			mapper_alert_type.alert_type_txt,
			alert.classification,
			alert.importance,
			mapper_alert_importance.importance_txt,
			alert.ongoing,
			(alert.start_time AT TIME ZONE 'utc'::text) AS start_time,
			(alert.stop_time AT TIME ZONE 'utc'::text) AS stop_time,
			COALESCE(alert.stop_time - alert.start_time, alert.last_updated::timestamp(0) without time zone - alert.start_time::timestamp(0) without time zone) AS duration,
			alert.countries,
			alert.direction,
			alert.fast_detected,
			alert.host_address,
			alert.impact_boundary,
			COALESCE(alert.impact_bps, 0) as impact_bps,
			COALESCE(alert.impact_pps, 0) as impact_pps,
			alert.ip_version,
			alert.misuse_types,
			alert.protocols,
			alert.severity_percent,
			alert.severity_threshold,
			alert.severity_unit,
			alert.managed_object_id,
			COALESCE(mapper_managed_object.managed_object_name, 'unkown'::text) AS managed_object_name,
			array_agg(DISTINCT COALESCE(v_alert_mitigations.subtype_txt, 'None')) AS mitigation_types,
			CASE
				WHEN sum(v_alert_mitigations.is_automitigation::integer) > 0 THEN true
				ELSE false
			END AS automitigation,
			CASE
				WHEN count(v_alert_mitigations.subtype) > 0 THEN true
				ELSE false
			END AS mitigated,
			COALESCE(sum(v_alert_mitigations.r_drop_bps_max) FILTER (WHERE v_alert_mitigations.subtype = 'tms'), 0) AS r_drop_bps_max_tms,
			COALESCE(sum(v_alert_mitigations.r_drop_pps_max) FILTER (WHERE v_alert_mitigations.subtype = 'tms'), 0) AS r_drop_pps_max_tms,
			COALESCE(sum(v_alert_mitigations.r_drop_bps_max) FILTER (WHERE v_alert_mitigations.subtype = 'flowspec'), 0) AS r_drop_bps_max_flowspec,
			COALESCE(sum(v_alert_mitigations.r_drop_pps_max) FILTER (WHERE v_alert_mitigations.subtype = 'flowspec'), 0) AS r_drop_pps_max_flowspec,
			COALESCE(sum(v_alert_mitigations.r_drop_bps_max) FILTER (WHERE v_alert_mitigations.subtype = 'blackhole'), 0) AS r_drop_bps_max_blackhole,
			COALESCE(sum(v_alert_mitigations.r_drop_pps_max) FILTER (WHERE v_alert_mitigations.subtype = 'blackhole'), 0) AS r_drop_pps_max_blackhole,
			COALESCE(sum(v_alert_mitigations.r_drop_bps_max) FILTER (WHERE v_alert_mitigations.subtype = 'flowspec' or v_alert_mitigations.subtype = 'tms'), 0) AS r_drop_bps_max_tms_and_flowspec,
			COALESCE(sum(v_alert_mitigations.r_drop_pps_max) FILTER (WHERE v_alert_mitigations.subtype = 'flowspec' or v_alert_mitigations.subtype = 'tms'), 0) AS r_drop_pps_max_tms_and_flowspec,
			COALESCE(sum(v_alert_mitigations.r_drop_bps_max) FILTER (WHERE v_alert_mitigations.subtype = 'flowspec' or v_alert_mitigations.subtype = 'tms' or v_alert_mitigations.subtype = 'blackhole'), 0) AS r_drop_bps_max_tms_and_flowspec_and_blackhole,
			COALESCE(sum(v_alert_mitigations.r_drop_pps_max) FILTER (WHERE v_alert_mitigations.subtype = 'flowspec' or v_alert_mitigations.subtype = 'tms' or v_alert_mitigations.subtype = 'blackhole'), 0) AS r_drop_pps_max_tms_and_flowspec_and_blackhole,
			COALESCE(sum(v_alert_mitigations.r_drop_bytes) FILTER (WHERE v_alert_mitigations.subtype = 'tms'), 0) AS r_drop_bytes_tms,
			COALESCE(sum(v_alert_mitigations.r_drop_packets) FILTER (WHERE v_alert_mitigations.subtype = 'tms'), 0) AS r_drop_packets_tms,
			COALESCE(sum(v_alert_mitigations.r_drop_bytes) FILTER (WHERE v_alert_mitigations.subtype = 'flowspec'), 0) AS r_drop_bytes_flowspec,
			COALESCE(sum(v_alert_mitigations.r_drop_packets) FILTER (WHERE v_alert_mitigations.subtype = 'flowspec'), 0) AS r_drop_packets_flowspec,
			COALESCE(sum(v_alert_mitigations.r_drop_bytes) FILTER (WHERE v_alert_mitigations.subtype = 'blackhole'), 0) AS r_drop_bytes_blackhole,
			COALESCE(sum(v_alert_mitigations.r_drop_packets) FILTER (WHERE v_alert_mitigations.subtype = 'blackhole'), 0) AS r_drop_packets_blackhole,
			COALESCE(sum(v_alert_mitigations.r_drop_bytes) FILTER (WHERE v_alert_mitigations.subtype = 'flowspec' or v_alert_mitigations.subtype = 'tms'), 0) AS r_drop_bytes_tms_and_flowspec,
			COALESCE(sum(v_alert_mitigations.r_drop_packets) FILTER (WHERE v_alert_mitigations.subtype = 'flowspec' or v_alert_mitigations.subtype = 'tms'), 0) AS r_drop_packets_tms_and_flowspec,
			COALESCE(sum(v_alert_mitigations.r_drop_bytes) FILTER (WHERE v_alert_mitigations.subtype = 'flowspec' or v_alert_mitigations.subtype = 'tms' or v_alert_mitigations.subtype = 'blackhole'), 0) AS r_drop_bytes_tms_and_flowspec_and_blackhole,
			COALESCE(sum(v_alert_mitigations.r_drop_packets) FILTER (WHERE v_alert_mitigations.subtype = 'flowspec' or v_alert_mitigations.subtype = 'tms' or v_alert_mitigations.subtype = 'blackhole'), 0) AS r_drop_packets_tms_and_flowspec_and_blackhole,
			(alert.last_updated AT TIME ZONE 'utc'::text) AS last_updated
			FROM alert
			JOIN mapper_alert_importance ON alert.importance = mapper_alert_importance.id
			JOIN mapper_alert_type ON alert.alert_type = mapper_alert_type.id::text
			LEFT JOIN mapper_managed_object ON alert.managed_object_id = mapper_managed_object.id
			LEFT JOIN v_alert_mitigations ON alert.id = v_alert_mitigations.alert_id
			GROUP BY alert.id, mapper_alert_type.alert_type_txt, mapper_alert_importance.importance_txt, mapper_managed_object.managed_object_name;
	
	/* v_alert_types__of_alerts */
	CREATE OR REPLACE VIEW v_alert_types__of_alerts
		AS
		SELECT alert_type_txt
			FROM v_alert
		GROUP BY alert_type_txt;
	
	/* v_directions__of_alerts */
	CREATE OR REPLACE VIEW v_directions__of_alerts
		AS
		SELECT direction
			FROM v_alert
		GROUP BY direction;
	
	/* v_managed_object_names__of_alerts */
	CREATE OR REPLACE VIEW v_managed_object_names__of_alerts
		AS
		SELECT managed_object_name
			FROM v_alert
		GROUP BY managed_object_name;
	
	/* v_security_levels__of_alerts */
	CREATE OR REPLACE VIEW v_security_levels__of_alerts
		AS
		SELECT importance_txt
			FROM v_alert
		GROUP BY importance_txt;

	/* v_mitigation_subtypes__of_alerts */
	CREATE OR REPLACE VIEW v_mitigation_subtypes__of_alerts
	AS
	SELECT unnest(v_alert.mitigation_types) AS mitigation_subtypes
		FROM v_alert
		GROUP BY (unnest(v_alert.mitigation_types));


	/* v_operational_info */
	CREATE OR REPLACE VIEW v_operational_info
	AS
	SELECT id,
		(alert__last_update AT TIME ZONE 'utc'::text) AS alert__last_update,
		(managed_object__last_update AT TIME ZONE 'utc'::text) AS managed_object__last_update
		FROM operational_info;

	
	'''
	]
	
	try:
		cur = pg_conn.cursor()
		
		for sql in sqls:
			#v_print(sql)
			cur.execute(sql)

		pg_conn.commit()
		v_print(' DONE')
		
	except (Exception, psycopg2.DatabaseError) as error:
		v_print(error)

			

def pg_UPSERT_alerts(alerts_with_mitigations):
	global pg_conn

	alerts = alerts_with_mitigations[0]
	alert_mitigations = alerts_with_mitigations[1]

	alerts_start_stop_time = {}
	if True:
		v_print('## Updating alerts table...', '')
		
		cur = pg_conn.cursor()
		for alert in alerts:
			alerts_start_stop_time[alert['id']] = {'start_time': alert['attributes']['start_time'], 'stop_time': alert['attributes'].get('stop_time')}
			mo_id = alert['relationships'].get('managed_object', {}).get('data', {}).get('id')
			if mo_id == None:
				if 'global_detection_settings' in alert['relationships']:
					mo_id = '71'
				else:
					v_print(alert)
					raise RuntimeError("unexpected MO issue")
			
			sql_values = [alert['id'],
				alert['attributes']['alert_class'],
				alert['attributes']['alert_type'],
				alert['attributes']['classification'],
				alert['attributes']['importance'],
				alert['attributes']['ongoing'],
				alert['attributes']['start_time'],
				alert['attributes'].get('stop_time'),
				alert['attributes']['subobject'].get('countries'),
				alert['attributes']['subobject']['direction'],
				alert['attributes']['subobject'].get('fast_detected', False),
				alert['attributes']['subobject'].get('host_address'),
				alert['attributes']['subobject'].get('impact_boundary'),
				alert['attributes']['subobject'].get('impact_bps'),
				alert['attributes']['subobject'].get('impact_pps'),
				alert['attributes']['subobject']['ip_version'],
				alert['attributes']['subobject'].get('misuse_types'),
				alert['attributes']['subobject'].get('protocols'),
				alert['attributes']['subobject']['severity_percent'],
				alert['attributes']['subobject']['severity_threshold'],
				alert['attributes']['subobject']['severity_unit'],
				mo_id,
				datetime.utcnow().isoformat()]
			sql = '''INSERT INTO alert
					 (id, alert_class, alert_type, classification,
					 importance, ongoing, start_time, stop_time, countries, direction,
					 fast_detected, host_address, impact_boundary, impact_bps, impact_pps,
					 ip_version, misuse_types, protocols, severity_percent, severity_threshold, severity_unit,
					 managed_object_id, last_updated)
					VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
					ON CONFLICT (id)
					DO UPDATE SET
					 alert_class = EXCLUDED.alert_class, alert_type = EXCLUDED.alert_type, classification = EXCLUDED.classification,
					 importance = EXCLUDED.importance, ongoing = EXCLUDED.ongoing, start_time = EXCLUDED.start_time,
					 stop_time = EXCLUDED.stop_time, countries = EXCLUDED.countries, direction = EXCLUDED.direction, fast_detected = EXCLUDED.fast_detected,
					 host_address = EXCLUDED.host_address, impact_boundary = EXCLUDED.impact_boundary, impact_bps = EXCLUDED.impact_bps,
					 impact_pps = EXCLUDED.impact_pps, ip_version = EXCLUDED.ip_version, misuse_types = EXCLUDED.misuse_types, protocols = EXCLUDED.protocols,
					 severity_percent = EXCLUDED.severity_percent, severity_threshold = EXCLUDED.severity_threshold,
					 severity_unit = EXCLUDED.severity_unit, managed_object_id = EXCLUDED.managed_object_id, last_updated = EXCLUDED.last_updated
					;'''
			cur.execute(sql, sql_values)
		pg_conn.commit()
		v_print(' DONE', )
			
		
	if True:
		v_print('## Updating alerts mitigation table...')
		cur = pg_conn.cursor()
		
		for alert_id in alert_mitigations:
			mitigations = alert_mitigations[alert_id]
		
			for mitigation in mitigations:
				mit_id = mitigation
				a_m_id = alert_id + '_' + mitigation
				
				mit_data = mitigations[mitigation]['data']
				mit_rates = mitigations[mitigation]['dropped_traffic_rates']
				
				sql_values = [a_m_id,
					mit_id,
					mit_data['relationships']['alert']['data']['id'],
					mit_data['attributes']['name'],
					mit_data['attributes']['subtype'],
					mit_data['attributes']['is_automitigation'],
					mit_data['attributes'].get('user'),
					mit_data['attributes']['ongoing'],
					mit_data['attributes'].get('start'),
					mit_data['attributes'].get('stop'),
	
					mit_rates['bps']['average'],
					mit_rates['bps']['max'],
					None,
					mit_rates['bps']['timeseries'],
					mit_rates['bps']['timeseries_start'],
					mit_rates['bps']['step'],
					
					mit_rates['pps']['average'],
					mit_rates['pps']['max'],
					None,
					mit_rates['pps']['timeseries'],
					mit_rates['pps']['timeseries_start'],
					mit_rates['pps']['step'],
					
					datetime.utcnow().isoformat()]
	
				sql = '''INSERT INTO alert_mitigations
						(id, mitigation_id, alert_id, name, subtype,
						is_automitigation, user_name,
						ongoing, start, stop,
						r_drop_bps_avg, r_drop_bps_max,
						r_drop_bps_sum, r_drop_bps_timeseries,
						r_drop_bps_timeseries_start, r_drop_bps_step,
						r_drop_pps_avg, r_drop_pps_max,
						r_drop_pps_sum, r_drop_pps_timeseries,
						r_drop_pps_timeseries_start, r_drop_pps_step,
						last_updated)
						VALUES (%s, %s, %s, %s, %s,
						%s, %s,
						%s, %s,%s,
						%s, %s,
						%s, %s,
						%s, %s,
						%s, %s,
						%s, %s,
						%s, %s,
						%s)
						ON CONFLICT (id)
						DO UPDATE SET
						mitigation_id = EXCLUDED.mitigation_id, alert_id = EXCLUDED.alert_id, name = EXCLUDED.name, subtype = EXCLUDED.subtype,
						is_automitigation = EXCLUDED.is_automitigation, user_name = EXCLUDED.user_name,
						ongoing = EXCLUDED.ongoing, start = EXCLUDED.start, stop = EXCLUDED.stop,
						r_drop_bps_avg = EXCLUDED.r_drop_bps_avg, r_drop_bps_max = EXCLUDED.r_drop_bps_max,
						r_drop_bps_sum = EXCLUDED.r_drop_bps_sum, r_drop_bps_timeseries = EXCLUDED.r_drop_bps_timeseries,
						r_drop_bps_timeseries_start = EXCLUDED.r_drop_bps_timeseries_start, r_drop_bps_step = EXCLUDED.r_drop_bps_step,
						r_drop_pps_avg = EXCLUDED.r_drop_pps_avg, r_drop_pps_max = EXCLUDED.r_drop_pps_max,
						r_drop_pps_sum = EXCLUDED.r_drop_pps_sum, r_drop_pps_timeseries = EXCLUDED.r_drop_pps_timeseries,
						r_drop_pps_timeseries_start = EXCLUDED.r_drop_pps_timeseries_start, r_drop_pps_step = EXCLUDED.r_drop_pps_step,
						last_updated = EXCLUDED.last_updated
						;
						
						'''
				cur.execute(sql, sql_values)
				sql = '''UPDATE alert_mitigations SET r_drop_pps_sum = (SELECT sum(s) * r_drop_pps_step FROM unnest(r_drop_pps_timeseries) s) where id = %s and r_drop_pps_sum IS NULL;'''
				cur.execute(sql, [a_m_id])
				sql = '''UPDATE alert_mitigations SET r_drop_bps_sum = (SELECT sum(s) * r_drop_bps_step FROM unnest(r_drop_bps_timeseries) s) where id = %s and r_drop_bps_sum IS NULL;'''
				cur.execute(sql, [a_m_id])
			
		pg_conn.commit()
		v_print('## Updating alerts mitigation table... DONE', )
		


def pg_UPSERT_managed_objects(managed_objects):
	global pg_conn
	
	v_print('## Updating managed objects table...', '')
	if True:
		cur = pg_conn.cursor()
		for managed_object in managed_objects:
			sql_values = [managed_object['id'], managed_object['attributes']['name'], datetime.utcnow().isoformat()]
			sql = '''INSERT INTO mapper_managed_object
					 (id, managed_object_name, last_updated)
					VALUES (%s, %s, %s)
					ON CONFLICT (id)
					DO UPDATE SET
					 managed_object_name = EXCLUDED.managed_object_name, last_updated = EXCLUDED.last_updated
					;'''
			cur.execute(sql, sql_values)
		pg_conn.commit()
		v_print(' DONE', )
		
		v_print('## Updating managed objects last_update timestamp...', '')
		sql = '''UPDATE operational_info SET managed_object__last_update = %s WHERE ID = 1;'''
		cur.execute(sql, [datetime.utcnow().isoformat()])
		pg_conn.commit()
		
		v_print(' DONE', )



def api_request(URL, key, body=None):
	api_response = None
	
	retry_cnt = 0
	request_OK = False
	
	while not request_OK:
		retry_cnt += 1
		try:
			if body is None:
				api_response = requests.get(URL, headers={'X-Arbux-APIToken': key, 'Content-Type': 'application/vnd.api+json'}, verify=CERT_verify, timeout=(15,90))
			else: 
				api_response = requests.post(URL, data=body, headers={'X-Arbux-APIToken': key, 'Content-Type': 'application/vnd.api+json'}, verify=CERT_verify, timeout=(15,90))
			request_OK = True
		except requests.exceptions.RequestException as e:
			v_print('')
			v_print(e)
			if retry_cnt < 3:
				v_print('... trying again')
				while True:
					pass
			else:
				v_print('... giving up and exit !!')
				exit(1)
	
	# Show any API error responses
	if (api_response.status_code < requests.codes.ok or api_response.status_code >= requests.codes.multiple_choices):
		print("\nAPI responded with this error: \n{}".format(api_response.text))

	return api_response.json()



def get_alerts(start_time = datetime(1970, 1, 1).isoformat(), alert_id = None):
	leader = SL_LEADER
	apikey = SL_APITOKEN
	
	if alert_id:
		v_print('### Alert retrieval - ID: ' + str(alert_id))
	else:
		v_print('### Alert retrieval')
		
	if alert_id != None:
		URI = "/api/sp/alerts/{}".format(alert_id)
		URL = "https://" + leader + URI
	else:
		URI = "/api/sp/alerts/?" + perPage + "&filter="
		#start_time = '2022-06-08T09:00:00Z' # for testing to limit runtime just fetching some alerts
		#stop_time = '2022-06-08T11:00:00Z' # for testing to limit runtime just fetching some alerts
		FILTERs = 	['/data/attributes/alert_class=dos',
					#'/data/attributes/alert_type=dos_host_detection', # for testing to limit runtime just fetching some alerts
					'/data/attributes/start_time>' + start_time#,
					#'/data/attributes/stop_time<' + stop_time # for testing to limit runtime just fetching some alerts
					]
		if alert_id != None:
			FILTERs += ['/data/id={}'.format(alert_id)]
		FILTER = ' AND '.join(FILTERs)
	
		FILTER = urllib.parse.quote(FILTER, safe='')

		api_page = 1
		URL = "https://" + leader + URI + FILTER + "&page={}".format(api_page)
	
	v_print('## retrieving alerts: 0%', '')	

	api_response = api_request(URL, apikey)
	
	if not 'errors' in api_response:
		if alert_id == None:
			api_data = api_response['data']
		else:
			api_data = [api_response['data']]
			
		if 'pagination' in api_response['meta']:
			api_page_last = api_response['meta']['pagination']['totalPages']
		else:
			api_page_last = None
		
		#if (api_page_last != None and api_page_last > 20): # for testing to limit runtime just fetching some alerts
		#	api_page_last = 1
		
		if api_page_last != None:
			for api_page in range(2,api_page_last+1):
				v_print(api_page)
				URL = "https://" + leader + URI + FILTER + "&page={}".format(api_page)
				api_response = api_request(URL, apikey)
				api_data.extend(api_response['data'])
				v_print(' {:.1f}%'.format((api_page/api_page_last)*100), '')
		
		if (api_page_last == None or api_page_last == 1):
			v_print(' 100% DONE')
		else:
			v_print(' DONE')
		
		if alert_id == None:
			v_print('## Alert count: {}'.format(len(api_data)))
	else:
		# handle missing previously onging alert (already deleted alerts?!)
		if alert_id != None:
			if api_response['errors'][0]['title'] == 'Missing resource error.':
				v_print(' 100% DONE -- BUT ALERT NOT FOUND ... deleted?')
				return [[None], {}] # [alert_data, alert_mitigations]
		# other api issues
		api_data = []
	
	alert_data = api_data
	
	# count alerts with mitigations
	alerts_with_mitigations = 0
	for alert in alert_data:
		if 'mitigation' in alert['relationships']:
			alerts_with_mitigations +=1
	alerts_mitigation_cnt = 0
	
	# check for associated mitigations
	alert_mitigations = {}
	for alert in alert_data:
		tms_mitigation_id_list = []
		fs_mitigation_id_list = []
		bh_mitigation_id_list = []
		
		alert_mitigations_temp = {}
		start_time = alert['attributes']['start_time'].split('+')[0] + 'Z'
		stop_time = alert['attributes'].get('stop_time', datetime.utcnow().isoformat().split('.')[0]).split('+')[0] + 'Z'
		
		if 'mitigation' in alert['relationships']:
			alerts_mitigation_cnt +=1
			v_print(' + {}/{} - Alert Mitigation information retrieval for AlertID: {}'.format(alerts_mitigation_cnt, alerts_with_mitigations, alert['id']))
			for mitigation in alert['relationships']['mitigation']['data']:
				alert_mitigations_temp[mitigation['id']] = {'alert_id': alert['id'], 'mitigation_id': mitigation['id'], 'data': None, 'dropped_traffic_rates': None}
				alert_mitigations_temp[mitigation['id']]['data'] = get_mitigation_data(mitigation['id'])
				if 'tms' in mitigation['id']:
					tms_mitigation_id_list.append(mitigation['id'])
				if 'flowspec' in mitigation['id']:
					fs_mitigation_id_list.append(mitigation['id'])
				if 'blackhole' in mitigation['id']:
					bh_mitigation_id_list.append(mitigation['id'])

		if tms_mitigation_id_list != []:
			for tms_mitigation_id in tms_mitigation_id_list:
				alert_mitigations_temp[tms_mitigation_id]['dropped_traffic_rates'] = get_tms_mitigation_rates(tms_mitigation_id, start_time, stop_time)
		
		if fs_mitigation_id_list != []:
			fs_mitigation_rates = get_alert_fs_mitigation_rates(alert['id'], fs_mitigation_id_list, start_time, stop_time)
			for fs_mitigation_id in fs_mitigation_rates:
				alert_mitigations_temp[fs_mitigation_id]['dropped_traffic_rates'] = fs_mitigation_rates[fs_mitigation_id]
		
		if bh_mitigation_id_list != []:
			bh_mitigation_rates = get_alert_bh_mitigation_rates(alert['id'], bh_mitigation_id_list, start_time, stop_time)
			# create fake BH mitigation with data from first actuall BH mitigation
			fake_bh_id = 'blackhole-fake4rates-'+str(alert['id'])
			alert_mitigations_temp[fake_bh_id] = {'alert_id': alert['id'], 'mitigation_id': fake_bh_id, 'data': None, 'dropped_traffic_rates': None}
			alert_mitigations_temp[fake_bh_id]['data'] = alert_mitigations_temp[bh_mitigation_id_list[0]]['data']
			
			for bh_mitigation_id in bh_mitigation_rates:
				alert_mitigations_temp[bh_mitigation_id]['dropped_traffic_rates'] = bh_mitigation_rates[bh_mitigation_id]

		if alert_mitigations_temp != {}:
			alert_mitigations[alert['id']] = alert_mitigations_temp

	return [alert_data, alert_mitigations]



def get_alert_bh_mitigation_rates(alert_id, bh_list, timeseries_start, timeseries_end):
	leader = SL_LEADER
	apikey = SL_APITOKEN
	
	alert_id = str(alert_id)
	
	v_print(' +++ Blackhole mitigation rate retrieval - Alert ID: ' + alert_id + ' ...', '')
	URI = "/api/sp/alerts/{}/traffic/misuse_types/?query_unit=bps&query_view=blackhole&timeseries_end={}&timeseries_start={}".format(alert_id, timeseries_end, timeseries_start)

	URL = "https://" + leader + URI
	api_response = api_request(URL, apikey)
	api_data_bps = api_response['data']
	
	URI = "/api/sp/alerts/{}/traffic/misuse_types/?query_unit=pps&query_view=blackhole&timeseries_end={}&timeseries_start={}".format(alert_id, timeseries_end, timeseries_start)
	URL = "https://" + leader + URI
	api_response = api_request(URL, apikey)
	api_data_pps = api_response['data']
	
	fake_bh_id = 'blackhole-fake4rates-'+alert_id
	
	drop_rates_dict = { fake_bh_id: {'bps': {'average': None, 'max': None, 'timeseries': None, 'step': None, 'timeseries_start': None}, 'pps': {'average': None, 'max': None, 'timeseries': None, 'step': None, 'timeseries_start': None}}}
	
	for data in api_data_bps:
		if 'misuse_types-7' in data.get('id'):
			bps_data = data['attributes']['view']['blackhole']['unit']['bps']
			drop_rates_dict[fake_bh_id]['bps']['step'] = bps_data['step']
			drop_rates_dict[fake_bh_id]['bps']['timeseries_start'] = bps_data['timeseries_start']
			drop_rates_dict[fake_bh_id]['bps']['average'] = bps_data['avg_value']
			drop_rates_dict[fake_bh_id]['bps']['max'] = bps_data['max_value']
			drop_rates_dict[fake_bh_id]['bps']['timeseries'] = bps_data['timeseries']
	
	for data in api_data_pps:
		if 'misuse_types-7' in data.get('id'):
			pps_data = data['attributes']['view']['blackhole']['unit']['pps']
			drop_rates_dict[fake_bh_id]['pps']['step'] = pps_data['step']
			drop_rates_dict[fake_bh_id]['pps']['timeseries_start'] = pps_data['timeseries_start']
			drop_rates_dict[fake_bh_id]['pps']['average'] = pps_data['avg_value']
			drop_rates_dict[fake_bh_id]['pps']['max'] = pps_data['max_value']
			drop_rates_dict[fake_bh_id]['pps']['timeseries'] = pps_data['timeseries']
			
	for bh_mit in bh_list:
		drop_rates_dict[bh_mit] = {'bps': {'average': None, 'max': None, 'timeseries': None, 'step': None, 'timeseries_start': None}, 'pps': {'average': None, 'max': None, 'timeseries': None, 'step': None, 'timeseries_start': None}}

	v_print(' DONE')
	
	return drop_rates_dict



def get_alert_fs_mitigation_rates(alert_id, fs_list, timeseries_start, timeseries_end):
	leader = SL_LEADER
	apikey = SL_APITOKEN
	
	v_print(' +++ Flowpsec mitigation rate retrieval - Alert ID: ' + str(alert_id) + ' ...', '')

	URI = "/api/sp/alerts/{}/traffic/flowspecs/?query_unit=bps&query_view=flowspec&timeseries_end={}&timeseries_start={}".format(alert_id, timeseries_end, timeseries_start)
	URL = "https://" + leader + URI
	api_response = api_request(URL, apikey)
	api_data_bps = api_response['data']
	
	URI = "/api/sp/alerts/{}/traffic/flowspecs/?query_unit=pps&query_view=flowspec&timeseries_end={}&timeseries_start={}".format(alert_id, timeseries_end, timeseries_start)
	URL = "https://" + leader + URI
	api_response = api_request(URL, apikey)
	api_data_pps = api_response['data']
	
	fs_data_temp = {}
	
	for fs in api_data_bps:
		fs_id = fs['relationships']['mitigation']['data']['id']
		fs_data_temp[fs_id] = {'bps': {'average': None, 'max': None, 'timeseries': None, 'step': None, 'timeseries_start': None}, 'pps': {'average': None, 'max': None, 'timeseries': None, 'step': None, 'timeseries_start': None}}
		bps_data = fs['attributes']['view']['flowspec']['unit']['bps']
		fs_data_temp[fs_id]['bps']['step'] = bps_data['step']
		fs_data_temp[fs_id]['bps']['timeseries_start'] = bps_data['timeseries_start']
		fs_data_temp[fs_id]['bps']['average'] = bps_data['avg_value']
		fs_data_temp[fs_id]['bps']['max'] = bps_data['max_value']
		fs_data_temp[fs_id]['bps']['timeseries'] = bps_data['timeseries']
	
	for fs in api_data_pps:
		fs_id = fs['relationships']['mitigation']['data']['id']
		if fs_id not in fs_data_temp:
			fs_data_temp[fs_id] = {'bps': {'average': None, 'max': None, 'timeseries': None, 'step': None, 'timeseries_start': None}, 'pps': {'average': None, 'max': None, 'timeseries': None, 'step': None, 'timeseries_start': None}}
		pps_data = fs['attributes']['view']['flowspec']['unit']['pps']
		fs_data_temp[fs_id]['pps']['step'] = pps_data['step']
		fs_data_temp[fs_id]['pps']['timeseries_start'] = pps_data['timeseries_start']
		fs_data_temp[fs_id]['pps']['average'] = pps_data['avg_value']
		fs_data_temp[fs_id]['pps']['max'] = pps_data['max_value']
		fs_data_temp[fs_id]['pps']['timeseries'] = pps_data['timeseries']
	
	drop_rates_dict = {}
	for fs_mit in fs_list:
		if fs_mit in fs_data_temp:
			drop_rates_dict[fs_mit] = fs_data_temp[fs_mit]
		else:
			drop_rates_dict[fs_mit] = {'bps': {'average': None, 'max': None, 'timeseries': None, 'step': None, 'timeseries_start': None}, 'pps': {'average': None, 'max': None, 'timeseries': None, 'step': None, 'timeseries_start': None}}
	
	v_print(' DONE')
	
	return drop_rates_dict



def get_tms_mitigation_rates(mitigation_id, timeseries_start, timeseries_end):
	leader = SL_LEADER
	apikey = SL_APITOKEN
	
	v_print(' +++ TMS mitigation rate retrieval - ID: ' + str(mitigation_id) + ' ...', '')
	
	URI = "/api/sp/mitigations/{}/rates_all_devices?timeseries_end={}&timeseries_start={}".format(mitigation_id, timeseries_end, timeseries_start )
	URL = "https://" + leader + URI
	api_response = api_request(URL, apikey)
	
	try:
		api_data = api_response['data']['attributes']
	except:
		print('!! ERROR !! -> API - URI: ')
		print(URI)
		print('')
		api_data = {}
	
	drop_rates = {'bps': {'timeseries_start': None, 'step': None}, 'pps': {'timeseries_start': None, 'step': None}}
	
	drop_rates['bps']['average'] = api_data.get('total', {}).get('drop', {}).get('bps', {}).get('average')
	drop_rates['bps']['max'] = api_data.get('total', {}).get('drop', {}).get('bps', {}).get('max')
	drop_rates['bps']['timeseries'] = api_data.get('total', {}).get('drop', {}).get('bps', {}).get('timeseries')
	if drop_rates['bps']['timeseries'] != None:
		drop_rates['bps']['timeseries_start'] = api_data['timeseries_start']
		drop_rates['bps']['step'] = api_data['step']
		
	drop_rates['pps']['average'] = api_data.get('total', {}).get('drop', {}).get('pps', {}).get('average')
	drop_rates['pps']['max'] = api_data.get('total', {}).get('drop', {}).get('pps', {}).get('max')
	drop_rates['pps']['timeseries'] = api_data.get('total', {}).get('drop', {}).get('pps', {}).get('timeseries')
	if drop_rates['pps']['timeseries'] != None:
		drop_rates['pps']['timeseries_start'] = api_data['timeseries_start']
		drop_rates['pps']['step'] = api_data['step']
		
	v_print(' DONE')
	
	return drop_rates



def get_mitigation_data(mitigation_id):
	leader = SL_LEADER
	apikey = SL_APITOKEN
	
	v_print(' +++ mitigation data retrieval - Mitigation ID: ' + str(mitigation_id) + ' ...', '')

	URI = "/api/sp/mitigations/{}".format(mitigation_id) 
	URL = "https://" + leader + URI
	api_response = api_request(URL, apikey)
	
	api_data = api_response['data']
	v_print(' DONE')

	return api_data



def get_managed_objects():
	leader = SL_LEADER
	apikey = SL_APITOKEN
	
	v_print('### Managed Objects retrieval')
	
	URI = "/api/sp/managed_objects/?" + perPage
	URL = "https://" + leader + URI
	
	v_print('## retrieving managed objects: 0%', '')	
	
	api_response = api_request(URL, apikey)
	
	api_data = api_response['data']
	
	if 'pagination' in api_response['meta']:
		api_page_last = api_response['meta']['pagination']['totalPages']
	else:
		api_page_last = None
	
	if api_page_last != None:
		for api_page in range(2,api_page_last+1):
			URL = "https://" + leader + URI + "&page={}".format(api_page)
			api_response = api_request(URL, apikey)
			api_data.extend(api_response['data'])
			v_print(' {:.1f}%'.format((api_page/api_page_last)*100), '')
	
	if (api_page_last == None or api_page_last == 1):
		v_print(' 100% DONE')
	else:
		v_print(' DONE')

	v_print('## Managed Object count: {}'.format(len(api_data)))
	return api_data



def update_managed_obects_fetch():
	v_print('#### Update Managed Objects fetch')
	MOs = get_managed_objects()
	pg_UPSERT_managed_objects(MOs)



def inital_alert_fetch():
	v_print('#### Initial Alert fetch')
	
	alerts = get_alerts()
	pg_UPSERT_alerts(alerts)
	
	v_print('## Updating alert last_update timestamp...', '')
	sql = '''UPDATE operational_info SET alert__last_update = %s WHERE ID = 1;'''
	cur = pg_conn.cursor()
	cur.execute(sql, [datetime.utcnow().isoformat()])
	pg_conn.commit()
	
	v_print(' DONE', )



def update_alert_fetch(all_alerts=False):
	v_print('#### Update Alert fetch')

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
	v_print('## Updating alert last_update timestamp...', '')
	sql = '''UPDATE operational_info SET alert__last_update = %s WHERE ID = 1;'''
	cur.execute(sql, [datetime.utcnow().isoformat()])
	pg_conn.commit()
	v_print(' DONE', )



def ongoing_alert_fetch():
	v_print('#### Ongoing Alert fetch')
	sql = '''SELECT id FROM alert WHERE ongoing = True;'''
	cur = pg_conn.cursor()
	cur.execute(sql)
	ongoing_alerts_rows = cur.fetchall()
	v_print('## Alert count: {}'.format(len(ongoing_alerts_rows)))
	
	for alert_row in ongoing_alerts_rows:
		alert_id = alert_row[0]
		alerts = get_alerts(alert_id=alert_id)
		if alerts[0] == [None]:
			# handle not anymore existing previously ongoing alerts
			sql = '''UPDATE alert SET stop_time = (SELECT last_updated FROM alert WHERE id = %s), ongoing = false WHERE id = %s;'''
			cur = pg_conn.cursor()
			cur.execute(sql, [alert_id, alert_id])
			pg_conn.commit()
			v_print(' !! Worked around it -> set alert to ongoing = false and stop_time to the last alert update timestamp')
			v_print(' !! You might want to run the script more often !')
		else:
			pg_UPSERT_alerts(alerts)




if __name__ == '__main__':
	v_print('#### Database connect')
	pg_connect()
	
	if init_environment:
		v_print('')
		v_print('#### Database init')
		pg_init()
		
		v_print('')
		inital_alert_fetch()

	v_print('')
	update_managed_obects_fetch()
	
	v_print('')
	update_alert_fetch()
	#update_alert_fetch(all_alerts=True) # to fetch all alerts each run
	
	v_print('')
	ongoing_alert_fetch()

	v_print('')
	v_print('#### Database close')
	pg_close()
	
	
	
	
	