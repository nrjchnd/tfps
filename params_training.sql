DELIMITER $$
CREATE EVENT `training_daily`
    ON SCHEDULE EVERY 1 DAY
    STARTS CURRENT_TIMESTAMP + INTERVAL 9 HOUR
    ON COMPLETION NOT PRESERVE
    ENABLE
    COMMENT 'Save Trained Parameters'
    DO BEGIN
		DROP TABLE IF EXISTS count_per_account;
		CREATE TABLE count_per_account AS
		SELECT date_format(time,'%Y-%m-%d') as period, 
		accountcode as accountcode, 
		SUM(IF(block_reason="A00" AND off_hours=0,1,0)) as auth_on, 
		SUM(IF(block_reason="A00" AND off_hours=1,1,0)) as auth_off, 
		SUM(IF(block_reason != "A00" AND off_hours=0,1,0)) as noauth_on, 
		SUM(IF(block_reason != "A00" AND off_hours=1,1,0)) as noauth_off, 
		MAX(IF(block_reason="A00" AND off_hours=0,concurrent_calls,0)) as sim_on, 
		MAX(IF(block_reason="A00" AND off_hours=1,concurrent_calls,0)) as sim_off
		FROM acc where time > (curdate() - interval 90 day) 
		GROUP BY date_format(time,'%Y-%m-%d'),accountcode;

		DROP TABLE IF EXISTS trained_params_per_account;
		CREATE TABLE trained_params_per_account AS
		SELECT accountcode as accountcode,
		avg(auth_on)+ 2*std(auth_on) as daily_quota,
		avg(auth_off)+ 2*std(auth_off) as daily_quota_off,
		avg(sim_on)+ 2*std(sim_on) as cc_calls,
		avg(sim_off)+ 2*std(sim_off) as cc_calls_off 
		FROM count_per_account GROUP BY accountcode;

		DROP TABLE IF EXISTS trained_countries_per_account;
		CREATE TABLE trained_countries_per_account AS
		SELECT accountcode,group_concat(distinct destination_country) as destination_countries,group_concat(distinct source_country) as source_countries 
		FROM acc 
		where time > (curdate() - interval 90 day) 
		GROUP by accountcode;
	END $$
DELIMITER ;