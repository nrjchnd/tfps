m4 defines.m4 tfps.m4 >/etc/opensips/opensips.cfg
m4 defines.m4 sip.conf.m4 >/etc/asterisk/sip.conf
m4 defines.m4 extensions.ael.m4 >/etc/asterisk/extensions.ael
m4 defines.m4 msmtprc.m4 >/etc/msmtprc
cp  extensions.conf /etc/asterisk/extensions.conf
cp  modules.conf /etc/asterisk/modules.conf
cp  asterisk.conf /etc/asterisk/asterisk.conf
cp tfpsctl /usr/bin
systemctl restart opensips
systemctl restart asterisk

