rm /tmp/* -rf
rm /etc/opensips/*
rm /etc/asterisk/extensions.ael
rm /etc/asterisk/sip.conf
rm defines.m4
mysql -e "delete from acc" fps
mysql -e "delete from subscriber" fps
cat /dev/null > /var/log/syslog
cat /dev/null > /var/log/opensips.log
cat /dev/null > /var/log/sip_acc.log
cat /dev/null > /var/log/auth.log
cat /dev/null > /var/log/btmp
cat /dev/null > /var/log/daemon.log
cat /dev/null > /var/log/asterisk/messages
cat /dev/null > /var/log/asterisk/queue_log





