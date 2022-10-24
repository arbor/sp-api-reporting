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
