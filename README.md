# tfps
Telephony Fraud Prevention System

<img src="https://user-images.githubusercontent.com/4958202/129224574-0f294ebd-3e48-4a19-83e7-fa09529f576c.jpg" width="250">

# Description

This project is an effective real time system to block Internet Revenue Share Fraud in SIP networks. It is based in blacklists and change analysis. We have discarded artificial inteligence due to the lagging response for fraud. I have provided instructions for Asterisk and FreePBX, consult us to connect other systems. 

Please do not use this project unless you know exactly what you are doing or use at your own risk, please read carefully the license before using. 

# Security Requirements

This project was created to run in AWS behind a firewall. The only system with access to this server should be the softswitch or PBX. 

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
ipabusedb key

# Installation

Deploy the database to MySQL 

```
mysql < schema.db
```

# Configure the system by editing the file defines.m4, pay attention to the backticks. Use nano or vi to edit the file 

vi defines.m4

```
divert(-1)
define(`PRIVATE_IP', `172.31.53.39')          #Private IP of the server
define(`PUBLIC_IP', `54.146.73.100')          #Public IP of the server
define(`PORT', `5060')                        #Port of the Server
define(`SQL_ACCOUNT',`root')                  #SQL account, always use root
define(`SQL_PASSWORD', `')                    #SQL password leave blank, mysql is running without external access
define(`ABUSE_DB_KEY', `a386a124f2474f95417eadff5bfa0badbae51c3dd81895c9d0e3e597e294b5a96108a0f5124064ab')  #IP abuse DB key (obtained at https://www.abuseipdb.com/)
define(`BUSINESS_HOURS',`America/New_York|20210104T090000|21000104T170000||WEEKLY|||MO,TU,WE,TH,FR')        #Define business hours, see format at the RFC2445 (Timezone|StartDate|EndDate|Periodicity|||Days of week)
define(`ISP_EMAIL',`from_email')                      #Email in the From address
define(`NOTIFICATION_EMAIL',`some_email')             #Email where to send the notifications
define(`AUTHORIZE_METHOD',`503')                      #503 - (Use 503/603 to authorize/deny calls), or 302 (Send 302 Redirect) 
define(`VERIFICATION_METHOD',`CAPTCHA')               #CAPTCHA/PIN (CAPTCHA, simpler for the user, PIN, safer, but have to be distributed)
define(`PIN',`6578')                                  #PIN to authorize calls if the method is PIN
define(`MAX_CAPTCHAATTEMPTS',`3')               #Max failed capctha_attempts
define(`CACHE_BLOCK_TIME',`3600')               #Block failed captcha for this time
define(`MAX_CONCURRENT',`5')                    #Maximum number of concurrent calls
define(`DESTINATION_COUNTRIES_BLACKLIST',`CU,LV,TN,DZ,MA,AF,IQ,LK,LH,MV,TD,GN,EE,MG')  #PRISM TOP FRAUD DESTINATIONS, DEFAULT LIST OF COUNTRIES BLOCKED
define(`SMTP_HOST',`some_host.some_domain')            #EMAIL ACCOUNT CONFIGURATION
define(`SMTP_EMAIL',`some_user@some_domain')     #EMAIL ACCOUNT CONFIGURATION
define(`SMTP_ACCOUNT','some_account')           #EMAIL ACCOUNT CONFIGURATION
define(`SMTP_USER',`some_user')                 #EMAIL ACCOUNT CONFIGURATION
define(`SMTP_PASSWORD',`some_password')         #EMAIL ACCOUNT CONFIGURATION
```

After filling the file defines.m4 (you will need an api key for ipabusedb https://www.abuseipdb.com/) with your own definitions, then run

```
./install.sh
```   

Restart OpenSIPS and Asterisk

# Client Installation

There are two modes of operation. 503/603 and Redirect.  In the 503/603 the system will respond with 603 each time it detects a fraud. This response shouldn't failover to the next gateway. When receiving a 503, the system should failover to the next gateway and complete the call. 

If in redirect mode, the system will return a 302 Moved Temporarily with a prefix A00 in the Request URI, in the client system, strip the A00 and complete the call. See the docs

# Admin Options

TFPS was designed to work hands free. However there are a few situations where you may want to interfere. For this we have the CLI utility tfpsctl. 

To remove a user use:

``` tfpsctl remove username domain ```

To reset the quotas of a user:

``` tfpsctl reset username domain ```

To list users 

``` tfpsctl list ```




