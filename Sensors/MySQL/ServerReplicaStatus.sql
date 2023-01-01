SELECT
    ('ON' = SERVICE_STATE) as ReplicationConnectionStatus,
    ('ON' = (SELECT SERVICE_STATE FROM performance_schema.replication_applier_status)) AS ReplicationApplierStatus,
    LAST_ERROR_NUMBER as LastErrorNumber,
    CONCAT('Error: ', LAST_ERROR_MESSAGE, ' at ', LAST_ERROR_TIMESTAMP) as LastError
FROM performance_schema.replication_connection_status;