# tfps
Telephony Fraud Prevention System

<img src="https://user-images.githubusercontent.com/4958202/129224574-0f294ebd-3e48-4a19-83e7-fa09529f576c.jpg" width="250">

# Availability

This product is available as an AWS AMI with technical support

![image](https://user-images.githubusercontent.com/4958202/135533852-5d3bdb71-31c5-4d05-801b-baeff084a04b.png)

https://aws.amazon.com/marketplace/pp/prodview-yug5okdjyzjgu

If you prefer you can use the open source version at your own risk.

# Description

This project is an effective real time system to block Internet Revenue Share Fraud in SIP networks. It is based in blacklists and change analysis. We have discarded artificial inteligence due to the lagging response for fraud. I have provided instructions for Asterisk and FreePBX, consult us to connect other systems. 

Please do not use this project unless you know exactly what you are doing or use at your own risk, please read carefully the license before using. 

# Security Requirements

This project was created to run in AWS behind a firewall. The only system with access to this server should be the softswitch or PBX. 

If you are running in AWS, please allow the UDP ports 5060 from your SIP server and 10000-20000 from any address. 

*** PLEASE DO NOT INSTALL THE SYSTEM WITHOUT A FIREWALL, THERE IS NO AUTHENTICATION BY DESIGN ***

# Requirements
This project requires:

Debian 10 Buster\
OpenSIPS 3.2 - All modules\
Asterisk 16  - Deafult installed with apt-get\
Asterisk TTS - https://zaf.github.io/asterisk-googletts/\
msmtp - smtp client\
mailutils - email client\
m4 - GNU m4 preprocessor\
ipabusedb key (https://www.abuseipdb.com/)
opensips control panel

# Installation

The installation is made using SSH. Please use ssh or putty to access your instance. 

Deploy the database to MySQL 

```
sudo mysql < fps.sql
```

# Configure the system by editing the file defines.m4, pay attention to the backticks. Use nano or vi to edit the file 

Go to the directory below 

```
cd /usr/src/tfps
cp defines.m4.example defines.m4
vi defines.m4
``` 

```
divert(-1)
define(`PRIVATE_IP', `172.31.92.20')
define(`PUBLIC_IP', `3.95.189.100')
define(`PORT', `5060')
define(`SQL_ACCOUNT',`root')
define(`SQL_PASSWORD', `')
define(`ABUSE_DB_KEY', `a386a124f2474f95417eadff5bfa0badbae51c3dd81895c9d0e3e597e294b5a96108a0f5124064ab')
define(`BUSINESS_HOURS',`America/New_York|20210104T090000|21000104T170000||WEEKLY|||MO,TU,WE,TH,FR')
define(`AUTHORIZE_METHOD',`302')
define(`VERIFICATION_METHOD',`CAPTCHA')
define(`PIN',`6578')
define(`MAX_CAPTCHAATTEMPTS',`3')               #Max failed capctha_attempts
define(`CACHE_BLOCK_TIME',`3600')               #Block failed captcha for this time
define(`MAX_CONCURRENT',`5')                    #Maximum number of concurrent calls
define(`DESTINATION_COUNTRIES_BLACKLIST',`CU,LV,TN,DZ,MA,AF,IQ,LK,LH,MV,TD,GN,EE,MG')  #PRISM TOP FRAUD DESTINATIONS
define(`PIN',`6578')
define(`NOTIFICATION_EMAIL',`flavio@voffice.com.br')
define(`SMTP_HOST',`smtp.gmail.com')
define(`SMTP_EMAIL',`wehostvoip@gmail.com')
define(`SMTP_ACCOUNT',`gmail')
define(`SMTP_USER',`wehostvoip')
define(`SMTP_PASSWORD',`P1p1l1n1#')
define(`SMTP_FROM',`cloud@wehostvoip.io')
define(`DEFAULT_CONCURRENT_CALLS',`2')
define(`DEFAULT_CONCURRENT_CALLS_OFF',`0')
define(`DEFAULT_QUOTA',`10')
define(`DEFAULT_QUOTA_OFF',`2')
define(`DEFAULT_SOURCE_COUNTRIES',`US')
define(`DEFAULT_DESTINATION_COUNTRIES',`US')
divert(0)
```

After filling the file defines.m4 (you will need an api key for ipabusedb https://www.abuseipdb.com/) with your own definitions, then run

```
sudo ./install.sh
```   

Restart OpenSIPS and Asterisk

```
systemctl restart opensips
systemctl restart asterisk
```

# Control panel installation
Follow all the instructions to install opensips control panel 9.3.2. After CP is running copy the customizations

```
copy /home/admin/tfps/opensips-cp /var/www/html
chown www-data:www-data /var/www/html -R
````

To access the control panel use your browser to access http://<ip_address>/cp

The username and password are admin:##fraudprevention##

## Please change immediately the password and restrict access to the control panel to an specific address ##

# Client Installation

There are two modes of operation. 503/603 and Redirect.  In the 503/603 the system will respond with 603 each time it detects a fraud. This response shouldn't failover to the next gateway. When receiving a 503, the system should failover to the next gateway and complete the call. 

If in redirect mode, the system will return a 302 Moved Temporarily with a prefix A00 in the Request URI, in the client system, strip the A00 and complete the call. See the docs

# Admin Options

TFPS was designed to work hands free. However there are a few situations where you may want to interfere. For this we have the CLI utility tfpsctl. 

To remove a user use:

``` sudo tfpsctl remove username domain ```

To reset the quotas of a user:

``` sudo tfpsctl reset username domain ```

To list users 

``` sudo tfpsctl list ```




