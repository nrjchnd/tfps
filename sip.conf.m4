[general]
;stealth mode
useragent=
sdpsession=-
context=dummy                
udpbindaddr=PRIVATE_IP:60101     
srvlookup=yes
nat=force_rport,comedia
externip=PUBLIC_IP
localnet=172.16.0.0/255.255.240.0
localnet=192.168.0.0/255.255.0.0
localnet=10.0.0.0/255.0.0.0

[sipserver]
username=sipserver@PUBLIC_IP
fromuser=sipserver
type=peer
host=PRIVATE_IP
port=PORT
directmedia=no
qualify=no
context=secure
