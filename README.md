# tfps
Telephony Fraud Prevention System

![TFPS LOGO INPI](https://user-images.githubusercontent.com/4958202/129224574-0f294ebd-3e48-4a19-83e7-fa09529f576c.jpg)

# Description

This project is an effective real time system to block Internet Revenue Share Fraud in SIP networks. It is based in blacklists and change analysis. We have discarded artificial inteligence due to the lagging response for fraud. 

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

Fill the file defines.m4 with your own definitions, then run

./install.sh

Restart OpenSIPS and Asterisk

# Client Installation

There are two modes of operation. 503/603 and Redirect.  In the 503/603 the system will respond with 603 each time it detects a fraud. This response shouldn't failover to the next gateway. When receiving a 503, the system should failover to the next gateway and complete the call. 

If in redirect mode, the system will return a 302 Moved Temporarily with a prefix A00 in the Request URI, in the client system, strip the A00 and complete the call. See the docs
