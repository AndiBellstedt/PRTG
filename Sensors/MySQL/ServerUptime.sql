-- calculates the uptime of the database in seconds
---SHOW GLOBAL STATUS LIKE 'Uptime';
SELECT Round(variable_value / (24 * 60 * 60), 1) as UptimeInDays, Round(variable_value / (60 * 60), 2) as UptimeInHours, DATE_SUB(now(), INTERVAL variable_value SECOND) "LastStartup" from performance_schema.global_status where variable_name='Uptime';
