#!/usr/bin/env python3

from datetime import datetime, timedelta

import logging
import os
from pathlib import Path
import psycopg2


class PGClient:
    def __init__(self, host, database, user, password):
        source_path = Path(__file__).resolve()
        self.sql_path = os.path.join(source_path.parent, 'sql')
        self.host = host
        self.user = user
        self.db = database
        self.password = password
        self.pg_conn = None
        
    def pg_connect(self):
        try:
            logging.info('Connecting to database...')
            
            self.pg_conn = psycopg2.connect(
                host=self.host,
                database=self.db,
                user=self.user,
                password=self.password)
            logging.info(' DONE')
            return self.pg_conn
        except (Exception, psycopg2.DatabaseError) as error:
            logging.error(error)
        return None

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
        try:
            pg_conn = self.pg_conn
            cur = pg_conn.cursor()
            sql_dir = self.sql_path
            for sql_file in (f'{sql_dir}/drop_views.sql',
                             f'{sql_dir}/drop_tables.sql',
                             f'{sql_dir}/create_tables.sql',
                             f'{sql_dir}/create_views.sql'):
                cur.execute(open(sql_file, 'r').read())
                pg_conn.commit()

            logging.info(' DONE')

        except (Exception, psycopg2.DatabaseError) as error:
            logging.error(error)

                

    def get_ongoing_alerts(self):
        try:
            pg_conn = self.pg_conn
            cur = pg_conn.cursor()
            sql = 'SELECT id FROM alert WHERE ongoing = True;'
            cur.execute(sql)
            return cur.fetchall() # This is a 2 dimensional array, rows with values

        except (Exception, psycopg2.DatabaseError) as error:
            logging.error(error)

        return None

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
            

    def fetch_timestamp(self, field: str):
        try:
            pg_conn = self.pg_conn
            cur = pg_conn.cursor()
            sql = f'SELECT {field} FROM operational_info WHERE ID = 1;'
            cur.execute(sql)
            last_update = cur.fetchall()[0][0]
            return last_update
        except (Exception, psycopg2.DatabaseError) as error:
            logging.error(error)

        # If no success above, return None
        return None

    def fetch_timestamp_alert(self):
        return self.fetch_timestamp('alert__last_update')

    def fetch_timestamp_managed_object(self):
        return self.fetch_timestamp('managed_object__last_update')

    def update_timestamp(self, field: str, update_time = None):
        try:
            pg_conn = self.pg_conn
            cur = pg_conn.cursor()
            update_timestamp = datetime.utcnow().isoformat()
            if update_time:
                update_timestamp = update_time.isoformat()
            sql = f'UPDATE operational_info SET {field} = \'{update_timestamp}\' WHERE ID = 1;'
            cur.execute(sql)
            pg_conn.commit()
        except (Exception, psycopg2.DatabaseError) as error:
            logging.error(error)

    def update_timestamp_alert(self, update_time):
        logging.info('## Updating alerts last_update timestamp...')
        self.update_timestamp('alert__last_update', update_time)
        logging.info('DONE')

    def update_timestamp_managed_object(self):
        logging.info('## Updating managed objects last_update timestamp...')
        self.update_timestamp('managed_object__last_update')
        logging.info('DONE')


    def check_table_row_count(self, table: str, exp_cnt: int):
        cnt = self.get_table_row_count(table)
        if cnt != exp_cnt:
            raise psycopg2.DataError(f'For table {table}, expected {exp_cnt} but found {cnt}')
        return True

    def get_table_row_count(self, table: str) -> int:
        pg_conn = self.pg_conn
        if not pg_conn:
            return 0
        try:
            cur = pg_conn.cursor()
            query_count_sql = f'SELECT COUNT(*) FROM {table};'
            cur.execute(query_count_sql)
            result = cur.fetchall()
            return result[0][0]

        except (Exception, psycopg2.DatabaseError) as error:
            logging.error(error)

        return 0


    def verify(self):
        logging.info('## Verifying expected data has been populated...')

        # Check that 7 tables have the expected number of rows
        try:
            # Check counts of certain tables
            self.check_table_row_count('alert', 0)
            self.check_table_row_count('alert_mitigations', 0)
            self.check_table_row_count('mapper_alert_importance', 3)
            self.check_table_row_count('mapper_alert_type', 3)
            self.check_table_row_count('mapper_mitigation_subtype', 3)
            self.check_table_row_count('mapper_managed_object', 6)
            self.check_table_row_count('operational_info', 1)
        except (psycopg2.DataError) as error:
            logging.error(error)
            return False

        # Check that at least one expected data value is there
        pg_conn = self.pg_conn
        if not pg_conn:
            return False
        try:
            cur = pg_conn.cursor()
            query_sql = 'SELECT managed_object_name FROM mapper_managed_object WHERE id = 10;'
            cur.execute(query_sql)
            result = cur.fetchall()
            if not result[0][0] == 'Dark IP':
                return False
        except (Exception, psycopg2.DatabaseError) as error:
            logging.error(error)

        logging.info('DONE')
        return True



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
