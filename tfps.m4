##
#
# Author: Flavio E. Goncalves
# Date: 07/30/2021
# Sip TFPS
# Version: 3
##

####### Global Parameters #########

/* uncomment the following lines to enable debugging */
#debug_mode=yes

log_level=3
xlog_level=3
log_stderror=no
log_facility=LOG_LOCAL0
server_header="Server: -"
user_agent_header="User-Agent: -"
server_signature=no
rev_dns=no
udp_workers=4
socket=udp:PRIVATE_IP:PORT as PUBLIC_IP # CUSTOMIZE ME

####### Modules Section ########

#set module path
mpath="/usr/lib/x86_64-linux-gnu/opensips/modules/"

#### SIGNALING module
loadmodule "signaling.so"

#### StateLess module
loadmodule "sl.so"

#### Transaction Module
loadmodule "tm.so"
modparam("tm", "fr_timeout", 5)
modparam("tm", "fr_inv_timeout", 30)
modparam("tm", "restart_fr_on_each_reply", 0)
modparam("tm", "onreply_avp_mode", 1)

#### Record Route Module
loadmodule "rr.so"
/* do not append from tag to the RR (no need for this script) */
modparam("rr", "append_fromtag", 0)

#### MAX ForWarD module
loadmodule "maxfwd.so"

#### SIP MSG OPerationS module
loadmodule "sipmsgops.so"

#### FIFO Management Interface
loadmodule "mi_fifo.so"
modparam("mi_fifo", "fifo_name", "/tmp/opensips_fifo")
modparam("mi_fifo", "fifo_mode", 0666)

#### ACCounting module
loadmodule "acc.so"
/* what special events should be accounted ? */
modparam("acc", "early_media", 0)
modparam("acc", "report_cancels", 0)
/* by default we do not adjust the direct of the sequential requests.
   if you enable this parameter, be sure to enable "append_fromtag"
   in "rr" module */
modparam("acc", "detect_direction", 0)
modparam("acc", "log_facility", "LOG_LOCAL1")
modparam("acc", "db_url", "mysql://root:SQL_PASSWORD@localhost/fps")
modparam("acc", "extra_fields", "db: REASON->block_reason; SOURCE_IP->source_ip; FROM->from_uri; TO->ruri; UA->ua; CONFIDENCE->abuseconfidence")
modparam("acc", "extra_fields", "log: REASON->block_reason; SOURCE_IP->source_ip; FROM->from_uri; TO->ruri; UA->ua; CONFIDENCE->abuseconfidence")

# ----- avpops params ----
loadmodule "avpops.so"
modparam("avpops", "db_url","mysql://root:SQL_PASSWORD@localhost/fps")
modparam("avpops", "avp_table", "usr_preferences")

# ---- dialplan parameters ----
loadmodule "dialplan.so"
modparam("dialplan", "db_url", "mysql://root:SQL_PASSWORD@localhost/fps")

# ----- pike params ----
loadmodule "pike.so"
modparam("pike", "sampling_time_unit", 10)
modparam("pike", "reqs_density_per_unit", 3000)
modparam("pike", "remove_latency", 120)

loadmodule "userblacklist.so"
modparam("userblacklist","db_url","mysql://root:SQL_PASSWORD@localhost/fps")

# ----- drouting params -----
loadmodule "drouting.so"
modparam("drouting","db_url","mysql://root:SQL_PASSWORD@localhost/fps")
modparam("drouting", "rule_prefix_avp", '$avp(dr_prefix)')

####### Extra modules section ########
loadmodule "db_mysql.so"
loadmodule "textops.so"
loadmodule "cachedb_local.so"
loadmodule "cfgutils.so"
loadmodule "exec.so"

loadmodule "rest_client.so"
modparam("rest_client", "ssl_verifypeer", 0)
modparam("rest_client", "ssl_verifyhost", 0)
loadmodule "json.so"
loadmodule "stir_shaken.so"

loadmodule "proto_udp.so"

####### Routing Logic ########
route{

    ## Pre-Admission checks common problems in a request, no parameters
    route(preadmission);

    ## Other checks, cancel, retransmissions, preloaded routes and rr
    route(cancel);

    # Initial requests handler
    route(initial);

    exit;
}

## Initial Requests Handler
route[initial] {

    $var(abusedb_key)="ABUSE_DB_KEY";
    $avp(quotaoffhours)=1;              #Initial daily quota off hours
    $avp(calloffhours)=1;               #Initial maximum amount of callsoffhours
    $avp(businesshours)="BUSINESS_HOURS";
    $avp(maxattempts)=5;                #maximum number of attempts
    $avp(timeattempts)=30;              #Time Between Attempts
    $avp(proxyip)="PRIVATE_IP";
    $avp(severity)=1;
    $avp(email)="NOTIFICATION_EMAIL";

    #Get the identity of the users
    
    #Default, get from the From header
    $avp(username)=$fU;
    $avp(domain)=$fd;

    if(is_present_hf("P-tfps")){
    
    # New standard, all parameters in a single header

        $avp(username)=$(hdr(P-tfps){s.select,0,;});
        $avp(domain)=$(hdr(P-tfps){s.select,1,;});
        $avp(sourceip)=$(hdr(P-tfps){s.select,2,;});
        $avp(ua)=$(hdr(P-tfps){s.select,3,;});
        $avp(simcalls)=$(hdr(P-tfps){s.select,4,;});
    
    } else {
    
    # Old Standard, all parameters in different headers
        if(is_present_hf("X-tfps")){
                $avp(username)=$(hdr(X-tfps){s.select,0,;});
                $avp(domain)=$(hdr(X-tfps){s.select,1,;});
        }
        
        #Get source IP
        if(is_present_hf("P-Received")) {
                $avp(sourceip):=$hdr(P-Received);
        } else {
                $avp(sourceip):=$si;
        }

        #Get user Agent
        if(is_present_hf("P-UA")) {
                $avp(ua):=$hdr(P-UA);
        } else {
                $avp(ua):=$ua;
        }

        #Get concurrent calls
        if(is_present_hf("P-Calls")) {
                $avp(simcalls)=$(hdr(P-Calls){s.int});
        }
    }    

    #Define IP address as public or private
    if( $(avp(sourceip){ip.matches,10.0.0.0/8}) ||
        $(avp(sourceip){ip.matches,127.0.0.0/8}) ||
        $(avp(sourceip){ip.matches,169.254.0.0/16}) ||
        $(avp(sourceip){ip.matches,172.16.0.0/12}) ||
        $(avp(sourceip){ip.matches,192.168.0.0/16} ) ) {
        $var(iptype)="private";
    } else {
        $var(iptype)="public";  
    }

    #Run the antifraud
    if(is_method("INVITE")) {
        $acc_extra(SOURCE_IP)=$avp(sourceip);
        $acc_extra(FROM)=$fu;
        $acc_extra(TO)=$ru;
        $acc_extra(UA)=$ua;
        do_accounting("db|log", "failed");
        route(check_for_fraud);
        exit;
    }
    record_route(); 
}

##Main routine to check for fraud
route[check_for_fraud] {

        xlog("L_INFO", "Fraudprev, f=$fu, r=$ru, ua=$ua, $avp(incountries), $avp(outcountries)");

        #By default all calls are autorized
        $avp(result):="A00";

        # Step 1, Check for risky User Agents in the dialplan database (Easy)
        if($ua!=null) {
                if(dp_translate(99997, "$avp(ua)/$avp(ua)",$avp(dest))) {  
                        xlog("L_INFO", "Fraud Detected: User Agent Blacklisted, f=$fu, r=$ru, ua=$ua");
                        #Drop the request, do not even send an answer to avoid the scan
                        $acc_extra(REASON)="User Agent Blacklisted";
                        t_reply(603,"Declined");
                        exit;
                }
        }
        
        # Step 2 Check against ip abusedb
        if($var(iptype)!="private") {
                #Cache results
                if(!cache_fetch("local","score_$avp(sourceip)",$var(abuse))) {
                        $var(url)="https://api.abuseipdb.com/api/v2/check?ipAddress="+$avp(sourceip);
                        rest_append_hf("Key:$var(abusedb_key)");
                        rest_get($var(url), $avp(http_response));
                        $json(rest_data):=$avp(http_response);
                        $var(abuse) = $json(rest_data/data/abuseConfidenceScore);
                        $acc_extra(CONFIDENCE)=$(var(abuse){s.int});
                        $var(incountry) = $json(rest_data/data/countryCode);
                        cache_store("local","score_$avp(sourceip)","$var(abuse)");
                        cache_store("local","country_$avp(sourceip)","$var(incountry)");
                        xlog("L_INFO",'Check ip report=$json(rest_data/data),score=$var(abuse), country=$var(incountry)');
                } else {
                        #fetch also the origination country
                        cache_fetch("local","country_$avp(sourceip)",$var(incountry));
                        cache_fetch("local","score_$avp(sourceip)",$var(abuse));
                        $acc_extra(CONFIDENCE)=$(var(abuse){s.int});
                        xlog("L_INFO","Check ip report from cache score=$var(abuse), country=$var(incountry) ");
                }

                if($(var(abuse){s.int})>=25) {
                        xlog("L_INFO","Fraud Detected: IP Blacklisted $avp(context),f=$fu, r=$ru, ua=$ua");
                        $acc_extra(REASON)="IP Blacklisted";
                        t_reply(603,"Declined");
                        exit;
                }

        }

        #Step 3 - Check for too may calls from A to B in a short period of time
        if($(avp(maxattempts){s.int})>0) {
                $avp(savedattempts)=0;
                cache_fetch("local", "same_$fU$rU" ,$avp(savedattempts));
                $var(currentattempts)=$(avp(savedattempts){s.int})+1;
                xlog("L_INFO","Check same A-B $var(currentattempts)/$avp(maxattempts) in $avp(timeattempts)");
                if($var(currentattempts)>$(avp(maxattempts){s.int})) {
                        xlog("L_INFO","Too many calls from same A-B in a short period of time $var(currentattempts)/$avp(maxattempts) in $avp(timeattempts)                                                                                                                   ");
                        $acc_extra(REASON)="Too many calls from same A-B in a short period of time";
                        #blockdestination for 1 hour
                        cache_store("local","block_$fU$rU","1",3600);
                        t_reply(603, "Declined");
                        exit;
                } else {
                        cache_store("local","same_$fU$rU","$var(currentattempts)",$avp(timeattempts));
                }
        }

        #step 4 - Check Stir/Shaken identity
        #route(verify_stir_shaken);

        #Detections ahead require user data
        #Get user data
        route(getuserdata);

        # Step 5 Check for country of origin (Easy)
        xlog("L_INFO","Source countries authorized $avp(source_countries), IP type=$var(type)");
        if($var(iptype)!="private") {
                #Check for a a new origin
                if($avp(source_countries)!~$var(incountry)) {
                        #Trying to call from a new country, this requires a captcha authorization in the media server
                        $rU="i"+$var(incountry)+$rU;
                        $acc_extra(REASON)="Source country not authorized";
                        $du="sip:PRIVATE_IP:60101";
                        #Relay to media server
                        t_relay();
                        exit;
                }
        }
        
        # Step 6  Check for destination country (Easy)
        xlog("L_INFO","Destination countries authorized $avp(destination_countries)");
        
        #Find the destionation country based on the prefix
        if(do_routing(99999,"C",,$avp(rule_attrs))) {
                #Country on $avp(rule_attrs)
                xlog("L_INFO","Prefix found $avp(dr_prefix),$avp(rule_attrs), $avp(destination_countries)");
                
                if($avp(destination_countries)=~$avp(rule_attrs)) {
                        xlog("L_INFO","Destination country Authorized: $avp(rule_attrs), $avp(username)@$avp(domain), f=$fu, r=$ru, ua=$ua");
                } else {
                        xlog("L_INFO","Possible Fraud Detected: Destination Country NOT Authorized: $avp(rule_attrs), f=$fu, r=$ru, ua=$ua");
                        $rU="d"+$avp(rule_attrs)+$rU;
                        $acc_extra(REASON)="Destination Country Not Authorized";
                        $du="sip:PRIVATE_IP:60101";
                        #Relay to media server
                        t_relay();
                        exit;
                }

        } else {
                xlog("L_WARN","International Prefix not found, f=$fu, r=$ru, ua=$ua");
                $acc_extra(REASON)="International Prefix Not Found";
                t_reply(603, "Declined");
                exit;
        }

        #Step 7 - Check for simultaneouscall from same A-B (Hard)
        
        #blockdestination for 1 hour
        if(cache_fetch("local", "block_$fU$rU", $avp(blockattempts))){
                xlog("L_INFO","Blocked for 1 hour in a short period of time $var(currentattempts)/$avp(maxattempts) in $avp(timeattempts)");
                $acc_extra(REASON)="Too many calls from same A-B in a short period of time";
                t_reply(603, "Declined");
                exit;
        }

        # Step 8 Check traffic depending on the business hours
        if(check_time_rec($avp(businesshours))) {
                #Regular Hours
                $avp(simcalls)=$(hdr(P-Calls){s.int});
                if($(avp(simcalls){s.int})>$(avp(callsonhours){s.int})) {
                        xlog("L_INFO","Fraud Detected: Too many simultaneous calls in normal hours id=$avp(security),$avp(simcalls),$avp(callsonhours)");
                        $acc_extra(REASON)="Too many calls on normal hours";
                        t_reply(603, "Declined");
                        exit;
                }
                #Check Daily Quota Regular Hours
                cache_add("local", "quota_$avp(accountcode)",1,86400);
                cache_fetch("local", "quota_$avp(accountcode)", $avp(totalcalls));
                if($(avp(totalcalls){s.int}) > $(avp(quotaonhours){s.int})) {
                        xlog("L_INFO","Fraud Detected: Call quota exceeded onhours id=$avp(security), $avp(quotaonhours)");
                        $acc_extra(REASON)="Quota exceeeded on normal hours";
                        t_reply(603, "Declined");
                        exit;
                }
        } else {
                $avp(simcalls)=$(hdr(P-Calls){s.int});
                if($(avp(simcalls){s.int})>$(avp(callsoffhours){s.int})) {
                        xlog("L_INFO","Fraud Detected: Too many simultaneous calls offhours id=$avp(security), $avp(simcalls), $avp(callsoffhours)");
                        $acc_extra(REASON)="Too many calls off hours";
                        t_reply(603, "Declined");
                        exit;
                }

                #Check Daily Quota Off-Hours
                cache_add("local", "quotaoff_$avp(accountcode)",1,86400);
                cache_fetch("local", "quotaoff_$avp(accountcode)", $avp(totalcalls));
                if($(avp(totalcalls){s.int}) > $(avp(quotaoffhours){s.int})) {
                        xlog("L_INFO","Fraud Detected: Calls exceeded quota off hours id=$avp(security), quota=$avp(quotaoffhours)");
                        $acc_extra(REASON)="Quota exceeded off hours";
                        $avp(severity)=3;
                        t_reply(603, "Declined");
                        exit;
                }
        }

        # Experimental, I'm a bit against abnormal detection. It is a delayed indicator, when triggered fraud has already happened
        ##Check if the volume is abnormal
        #cache_fetch("local", "total_$avp(accountcode)", $avp(dailycalls));
        #if( $avp(dailycalls)>10 ) {
        #        if( avp_db_query("select avg,std,($avp(dailycalls)-avg)/std*100 from daily_stats_approved where accountcode=$avp(accountcode) order by time desc limit 1","$avp(avg),$avp(std),$avp(zscore)")) {
        #                if($(avp(zscore){s.int})>196) xlog ("L_INFO", "ABNORMAL TRAFFIC from $avp(accountcode), calls=$avp(dailycalls) average=$avp(avg) zscore=$avp(zscore)");
        #        } else {
        #                if($(avp(zscore){s.int})>196) xlog ("L_INFO", "NORMAL TRAFFIC from $avp(accountcode), calls=$avp(dailycalls) average=$avp(avg) zscore=$avp(zscore)");
        #        }
        #}

        #Call was accepted
        route(handle_authorized);
        exit;
}

route[getuserdata] {
        xlog("L_INFO","Tempo: $time(%F %H:%M:%S) \n");
        $avp(calltime)=$time(%F %H:%M:%S);
       
        if(!avp_db_query("SELECT cc_calls,daily_quota,source_countries,destination_countries FROM subscriber s WHERE s.username='$avp(username)' AND s.domain='$avp(domain)'", "$avp(cc_calls); $avp(daily_quota); $avp(source_countries), $avp(destination_countries)")) {
                xlog("L_INFO","User does not exist");
                $acc_extra(REASON)="User does not exist";
                route(onboarding);
                exit;
        }

        xlog("L_INFO","GETUSERDATA-> calls concurrent_calls=$avp(cc_calls) daily quota=$avp(daily_quota)");
        $avp(accountcode)=$avp(username)+"@"+$avp(domain);
        cache_add("local", "quota_$avp(accountcode)",1,86400);
        cache_fetch("local", "quota_$avp(accountcode)", $avp(totalcalls));
        xlog("L_INFO","->getuserdata<- ru=$ru, fu=$fu, rm=$rm si=$si username=$avp(username), domain=$avp(domain), quota=$avp(totalcalls)\n");
        return;
}

route[onboarding] {
        #We use the prefix o to route to onboarding in the media server, while is not very legible it is small enough to avoid passing the limit of 1500 bytes
        prefix("o");
        $du="sip:PRIVATE_IP:60101";
        t_relay();
        exit;
}

route[handle_authorized] {
        #There are two methods to authorize ,redirect with A00 or 503
        $rd=$fd;
        $ru="sip:"+$avp(result)+$rU+"@"+$rd;
        $acc_extra(REASON)="Call Authorized";
        t_reply(302, "Moved Temporarily");
        exit;
}

route[email] {
    # stop script processing if transaction exists

    # Tempo de espera entre emails 30 minutos

    if(!cache_fetch("local","timer_$avp(acocuntcode)", $avp(dummy))) {

        cache_store("local","timer_$avp(accountcode)","1",3600);

        if($avp(result)=="R08") {
                xlog("L_INFO","Email enviado para $avp(email) R08");
                exec('EMAIL=$avp(email); if [-z "$$EMAIL" ]; then exit 1; fi; echo "[TFPS Real Time Alert] Simultanous calls off hours exceeded from $$SIP_HF_FROM for $$SIP_OUSER" | mail -s "Simultanous calls off hours exceeded from $avp(sourceip), dialed number $var(original)" -S from:tfps@tfps.co $avp(email) -c tfps@tfps.co');
        }

        if($avp(result)=="R09") {
                xlog("L_INFO","Email enviado para $avp(email) R09");
                exec('EMAIL=$avp(email); if [-z "$$EMAIL" ]; then exit 1; fi; echo "[TFPS Real Time Alert] Call quota off hours exceeded from $$SIP_HF_FROM for $$SIP_OUSER" | mail -s "Call quota off hours exceeded from $avp(sourceip), dialed number $var(original)" -S from:tfps@tfps.co $avp(email) -c tfps@tfps.co');
        }

        if($avp(result)=="R10") {
                xlog("L_INFO","Email enviado para $avp(email) R10");
                exec('EMAIL=$avp(email); if [-z "$$EMAIL" ]; then exit 1; fi; echo "[TFPS Real Time Alert] Simultaneous calls exceeded from $$SIP_HF_FROM for $$SIP_OUSER" | mail -s "Simultaneous calls exceeded from $avp(sourceip), dialed number $var(original)" -S from:tfps@tfps.co $avp(email) -c tfps@tfps.co');
        }

        if($avp(result)=="R11") {
                xlog("L_INFO","Email enviado para $avp(email) R11");
                exec('EMAIL=$avp(email); if [-z "$$EMAIL" ]; then exit 1; fi; echo "[TFPS Real Time Alert] Call quota exceeded from $$SIP_HF_FROM for $$SIP_OUSER" | mail -s "Call quota exceeded from $avp(sourceip), dialed number $var(original)" -S from:tfps@tfps.co $avp(email) -c tfps@tfps.co');
        }
    }
    xlog("L_INFO","Tempo: $avp(calltime) \n");
    xlog("L_INFO","Email sent to $avp(email)");
    
}

route[cancel] {
    #CANCEL processing
    if (is_method("CANCEL"))  {
        if (t_check_trans()){
            t_relay();
            exit;
        }
    }

    #Retransmissions handler
    t_check_trans();
}

route[preadmission] {

    #Drop Options
    if(is_method("OPTIONS")){
        exit;
    }

    #Loop detection
    if($rU=~"^A|^R"){
        sl_send_reply(482,"Loop Detected");
        exit;
    }

    ##Discard ACKs
    if(is_method("ACK")){
        t_check_trans();
        exit;
    }

    if(!is_method("INVITE")) {
        sl_send_reply(405,"Method not supported");
        exit;
    }

    ## Check for incomplete addressess
    if ($rU==NULL) {
        sl_send_reply(484,"Address Incomplete");
        exit;
    }

    #Check for loops
    if (!mf_process_maxfwd_header(70)) {
        t_reply(483, "Too many hops");
        exit;
    }

    #Check for flooding
    if(!pike_check_req()) {
        $acc_extra(REASON)="Flooding";
        xlog("L_WARN","Flooding detected for the address $si, RURI=$ru,From=$fu\n");
        drop();
        exit;
    }

    # Detect sql injection
    if($au =~ "(\=)|(\-\-)|(')|(\%27)|(\%24)|(\%60) && $au!=null") {
        xlog("L_INFO","Someone from $si is doing an sql injection attack, blocking! au=$au");
        $acc_extra(REASON)="SQL injection";
        t_reply(603,"Declined");
        exit;
    }

    if($ru =~ "(\=)|(\-\-)|(')|(\%27)|(\%24)|(\%60) && $au!=null") {
        xlog("L_INFO","Someone from $si is doing an sql injection attack, blocking! au=$au");
        $acc_extra(REASON)="SQL injection";
        t_reply(603,"Declined");
        exit;
    }

    if($(ct.fields(uri){uri.user}) =~ "(\=)|(\-\-)|(')|(\%27)|(\%24)|(\%60)") {
        xlog("L_INFO","Someone from $si is doing an sql injection attack, blocking! ct=$ct");
        $acc_extra(REASON)="SQL injection";
        t_reply(603,"Declined");
        exit;
    }

    if($(ct.fields(uri){uri.host}) =~ "(\=)|(\-\-)|(')|(\%27)|(\%24)|(\%60)") {
        xlog("L_INFO","Someone from $si is doing an sql injection attack, blocking! ct=$ct");
        $acc_extra(REASON)="SQL injection";
        t_reply(603,"Declined");
        exit;
    }

    if($fu =~ "(\=)|(\-\-)|(')|(\%27)|(\%24)|(\%60)") {
        xlog("L_INFO","Someone from $si is doing an sql injection attack, blocking! ct=$ct");
        $acc_extra(REASON)="SQL injection";
        t_reply(603,"Declined");
        exit;
    }
}

#Verify Identity Header
route[verify_stir_shaken] {
        # certificate managing
        $var(found) = cache_fetch("local", $identity(x5u),$var(cert));
        if (!$var(found) || !stir_shaken_check_cert("$var(cert)")) {
                # if the certificate is not found in the cache
                # or is expired, we try to fetch it from the
                # certificate repository
                rest_get( "$identity(x5u)", $var(cert),$var(ctype), $var(http_rc));
                if ($rc<0 || $var(http_rc) != 200) {
                        t_reply(436, "Bad Identity Info");
                        exit;
                }
                # certificate successfully fetched, cache it now
                cache_store("local", $identity(x5u), $var(cert));
        }

        # do the STIR/SHAKEN verification
        stir_shaken_verify( "$var(cert)", $var(err_sip_code),$var(err_sip_reason));
        if ($rc < 0) {
                xlog("stir_shaken_verify() failed: $var(code), $var(reason) \n");
                t_reply( $var(err_sip_code), 
                $var(err_sip_reason));
                exit;
        }
}
