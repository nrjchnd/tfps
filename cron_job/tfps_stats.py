#!/usr/bin/env python
import mysql.connector

mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  password="",
  database="fps"
)

cursor = mydb.cursor()

#Clean old records 
cursor.execute("delete from acc where time < now() - interval 90 DAY;")
cursor.execute("delete from daily_stats_approved where time < now() - interval 90 DAY;")
cursor.execute("delete from daily_stats_approved_off where time < now() - interval 90 DAY;")
cursor.execute("delete from daily_stats_rejected where time < now() - interval 90 DAY;")
cursor.execute("delete from daily_stats_rejected_off where time < now() - interval 90 DAY;")
cursor.execute("delete from account_stats_approved where lastUpdated < now() - interval 90 DAY;")
cursor.execute("delete from account_stats_approved_off where lastUpdated < now() - interval 90 DAY;")
cursor.execute("delete from account_stats_rejected where lastUpdated < now() - interval 90 DAY;")
cursor.execute("delete from account_stats_rejected_off where lastUpdated < now() - interval 90 DAY;")

#Update daily statistics per account
cursor.execute('insert into daily_stats_approved (time,accountcode,counter) select date(time),accountcode,count(*) from acc where response like "A%" and  (DAYOFWEEK(time)>=2 and DAYOFWEEK(time)<=6) and time>=DATE_ADD(CURDATE(),INTERVAL -2 DAY) group by  date(time),accountcode;')
cursor.execute('insert into daily_stats_approved_off (time,accountcode,counter) select date(time),accountcode,count(*) from acc where response like "A%" and  (DAYOFWEEK(time)=1 or DAYOFWEEK(time)=7) and time>=DATE_ADD(CURDATE(),INTERVAL -2 DAY) group by date(time),accountcode;')
cursor.execute('insert into daily_stats_rejected (time,accountcode,counter) select date(time),accountcode,count(*) from acc where response like "R%" and  (DAYOFWEEK(time)>=2 and DAYOFWEEK(time)<=6) and time>=DATE_ADD(CURDATE(),INTERVAL -2 DAY) group by  date(time),accountcode;')
cursor.execute('insert into daily_stats_rejected_off (time,accountcode,counter) select date(time),accountcode,count(*) from acc where response like "R%" and (DAYOFWEEK(time)=1 or DAYOFWEEK(time)=7) and time>=DATE_ADD(CURDATE(),INTERVAL -2 DAY) group by  date(time),accountcode;')

#Update counters per account to define optimal quotas
cursor.execute("INSERT into account_stats_approved (accountcode,avg,std,zscore) select accountcode,avg(counter),std(counter),(counter-avg(counter))/std(counter) from daily_stats_approved where (time < now() - interval 90 DAY) on duplicate key UPDATE;")
cursor.execute("INSERT into account_stats_approved_off (accountcode,avg,std,zscore) select accountcode,avg(counter),std(counter),(counter-avg(counter))/std(counter) from daily_stats_approved_off where time < now() - interval 90 DAY on duplicate key UPDATE;")
cursor.execute("INSERT into account_stats_rejected (accountcode,avg,std,zscore) select accountcode,avg(counter),std(counter),(counter-avg(counter))/std(counter) from daily_stats_rejected where time < now() - interval 90 DAY on duplicate key UPDATE;")
cursor.execute("INSERT into account_stats_rejected_off (accountcode,avg,zscore) select accountcode,avg(counter),std(counter),(counter-avg(counter))/std(counter) from daily_stats_rejected_off where time < now() - interval 90 DAY on duplicate key UPDATE;")