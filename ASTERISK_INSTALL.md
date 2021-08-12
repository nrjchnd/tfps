# Asterisk Integration Guide

FPS is a simple system to protect your PBX from fraudulent calls. It is very easy to integrate to your PBX. After creating your account and setting your calling policies, you will need to configure your Asterisk or FreeSwitch box. FPS can work like a SIP Provider or a SIP redirect server, but instead of completing your call, in prevention mode, it redirects your call back with a three-character, prefix. After receiving vthis prefix, you can decide what to do in your dial plan. The system can be installed in FREE detection mode (only email alert) or in the sophisticated and complete prevention mode (redirects).

## Method 1: Redirect

![image](https://user-images.githubusercontent.com/4958202/129259612-e0d50891-85fa-4f4c-9cff-b100e74f1b76.png)

if you have configured your TFPS server to run as a redirect server, you should follow the instructions below. 

sip.conf

```
[fps]
type=peer
context=fps
host=<your tfps server>
port=5060
``` 

extensions.conf

```
[from-internal] ; Set there the context for your users
;FPS for International Calls
exten=_011[1-9].,1,set(GROUP()=fps)
same=>n,set(ncalls=${GROUP_COUNT(fps)})
same=>n,set(_original=${EXTEN})
same=>n,SIPAddHeader(P-tfps: ${CALLERID(num)};${SIPDOMAIN};${CHANNEL(recvip)};${CHANNEL(useragent)};${ncalls})
same=>n,dial(SIP/fps/${EXTEN:2})

;For calls approved 
exten=_A.,1,Answer()
same=>n,Dial(SIP/provider/${original});(Customize here to send the call ahead)
same=>n,hangup(16)
```

Response Codes
302 - Moved Temporarily with a prefix of A00 – Call Approved
603 - Call not approved

## Method 2: Failover

![image](https://user-images.githubusercontent.com/4958202/129259391-56734c5c-9c4b-489a-b79a-3874de39c7b6.png)

if you have configured your TFPS server to run as a redirect server, you should follow the instructions below. 

sip.conf

```
[fps]
type=peer
context=fps
host=<your tfps server>
port=5060

[provider]
type=peer
context=fps
host=<your provider server>
port=5060
``` 

extensions.conf
```
[from-internal] ; Set there the context for your users
;FPS for International Calls
exten=_011[1-9].,1,set(GROUP()=fps)
same=>n,set(ncalls=${GROUP_COUNT(fps)})
same=>n,SIPAddHeader(P-tfps: ${CALLERID(num)};${SIPDOMAIN};${CHANNEL(recvip)};${CHANNEL(useragent)};${ncalls})
same=>n,dial(SIP/fps/${EXTEN})
same=>n,goto(${DIALSTATUS})
same=>n,hangup()
same=>n(BUSY),playback(unauthorized)
same=>n,hangup()
same=>n(CONGESTION),
same=>n,Dial(SIP/provider/${EXTEN})
```

DISCLAIMER
No service can guarantee 100% that you will not be a victim of fraud. We can remove 99.999% of all attacks using our system, but it is wise apply also other measures. We strongly advise you to, beyond installing this system, take other measures not limited to:
1.	Do not allow Internet Access to your PBX web interface. Most web interfaces are highly vulnerable.
2.	Prefer limited prepaid SIP trunking for international calls instead of post-paid unlimited TDM trunks.
3.	Use strong passwords always.

TECH-SUPPORT
Please send any tech support requests to cloud@wehostvoip.io
