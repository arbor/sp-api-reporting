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

/* mapper_alert_importance */
CREATE TABLE mapper_alert_importance (
    id smallint NOT NULL PRIMARY KEY,
    importance_txt character varying(6));
INSERT INTO mapper_alert_importance VALUES (0, 'Low');
INSERT INTO mapper_alert_importance VALUES (2, 'High');
INSERT INTO mapper_alert_importance VALUES (1, 'Medium');

/* mapper_alert_type */
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
