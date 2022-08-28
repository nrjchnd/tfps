shred -u  /tmp/* 
shred -u  /etc/opensips/*
shred -u  /etc/asterisk/extensions.ael
shred -u  /etc/asterisk/sip.conf
shred -u  defines.m4
mysql -e "delete from acc" fps
mysql -e "delete from subscriber" fps
for file in /var/log/*; do cat /dev/null >${file}; done
for file in /var/log/unattended-upgrades/*; do shred -u ${file}; done
cat /dev/null > /var/log/asterisk/messages
cat /dev/null > /var/log/asterisk/queue_log
shred -u /root/.*history
shred -u /home/admin/.*history
shred -u /etc/ssh/*_key /etc/ssh/*_key.pub
shred -u /home/admin/.ssh/*
shred -u /root/.ssh/*
