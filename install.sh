sudo git pull
sudo m4 defines.m4 tfps.m4 >/etc/opensips/opensips.cfg
sudo m4 defines.m4 sip.conf.m4 >/etc/asterisk/sip.conf
sudo m4 defines.m4 extensions.ael.m4 >/etc/asterisk/extensions.ael
sudo m4 defines.m4 msmtprc.m4 >/etc/msmtprc
sudo cp  extensions.conf /etc/asterisk/extensions.conf
sudo cp  modules.conf /etc/asterisk/modules.conf
sudo cp  asterisk.conf /etc/asterisk/asterisk.conf
sudo cp  tfpsctl /usr/bin
sudo systemctl restart opensips
sudo systemctl restart asterisk

