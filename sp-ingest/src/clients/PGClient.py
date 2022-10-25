#!/usr/bin/env python3

from datetime import datetime, timedelta

import logging

import psycopg2


class PGClient:
    def __init__(self, host, database, user, password):
        self.host = host
        self.user = user
        self.db = database
        self.password = password
        self.pg_conn = None
        
    def pg_connect(self):
        try:
            logging.info(' Connecting to database...')
            
            self.pg_conn = psycopg2.connect(
                host=self.host,
                database=self.db,
                user=self.user,
                password=self.password)
            logging.info(' DONE')
            return self.pg_conn
        except (Exception, psycopg2.DatabaseError) as error:
            logging.error(error)

    def pg_close(self):
        try:
            if self.pg_conn is not None:
                logging.info('Closing database')
                self.pg_conn.close()
                logging.info(' DONE')
                
            else:
                logging.error('!! ERROR: No database connection to close')
        except (Exception, psycopg2.DatabaseError) as error:
            logging.error(error)

    def pg_version(self):
        if self.pg_conn is not None:
            logging.info('## PostgreSQL database version: ')
            
            cur = self.pg_conn.cursor()
            cur.execute('SELECT version();')
        
            db_version = cur.fetchone()
            
            logging.info(db_version)
        else:
            logging.error('!! ERROR: No database connection')
    
    def pg_init(self):
        logging.info('Creating database table and views ...')
                
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
            cur = self.pg_conn.cursor()
            
            for sql in sqls:
                #logging.info(sql)
                cur.execute(sql)

            self.pg_conn.commit()
            logging.info(' DONE')
            
        except (Exception, psycopg2.DatabaseError) as error:
            logging.info(error)

                

    def pg_UPSERT_alerts(self, alerts_with_mitigations):
        alerts = alerts_with_mitigations[0]
        alert_mitigations = alerts_with_mitigations[1]

        alerts_start_stop_time = {}
        logging.info('## Updating alerts table...')
        
        cur = self.pg_conn.cursor()
        for alert in alerts:
            alerts_start_stop_time[alert['id']] = {'start_time': alert['attributes']['start_time'], 'stop_time': alert['attributes'].get('stop_time')}
            mo_id = alert['relationships'].get('managed_object', {}).get('data', {}).get('id')
            if mo_id == None:
                if 'global_detection_settings' in alert['relationships']:
                    mo_id = '71'
                else:
                    logging.info(alert)
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
        self.pg_conn.commit()
        logging.info(' DONE')
            
        logging.info('## Updating alerts mitigation table...')
        cur = self.pg_conn.cursor()
        
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
            
            self.pg_conn.commit()
            logging.info('## Updating alerts mitigation table... DONE')
            



    def pg_UPSERT_managed_objects(self, managed_objects):
        logging.info('## Updating managed objects table...')
        if True:
            cur = self.pg_conn.cursor()
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
            self.pg_conn.commit()
            logging.info(' DONE')
            
            logging.info('## Updating managed objects last_update timestamp...')
            sql = '''UPDATE operational_info SET managed_object__last_update = %s WHERE ID = 1;'''
            cur.execute(sql, [datetime.utcnow().isoformat()])
            self.pg_conn.commit()
            
            logging.info(' DONE')
