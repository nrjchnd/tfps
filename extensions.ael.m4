globals {
    pin=PIN;
	account=SQL_ACCOUNT;
	sql_password=SQL_PASSWORD;
	LANG=en;
}

context secure {
	//New source country
	_i.=>{
		&getuserdomain();
		&new_country(${EXTEN:1:2});
	}

	//New destination country
	_d.=>{
		&getuserdomain();
		&new_destination_country(${EXTEN:1:2});
	}

	_q.=>{
		&getuserdomain();
		&new_call_quota();
	}

	_n.=>{
		&getuserdomain();
		&new_call_quota_off();
	}

	//New user
	_o.=>{
		&getuserdomain();
		goto onboarding,s,1 ;
	}

	_X.=>{
		hangup(16);
	}

}


//Handling the first call
context full_onboarding {
	s=>{
		Progress();
		Set(TIMEOUT(digit)=5);
		agi(googletts.agi,"Thanks for calling, as this is your first international call, I have to apply a security check",${LANG});
		&verify();
		if(${verify_return}==true) {
			agi(googletts.agi,"To set your parameters, I have to ask you two simple questions, these questions will be asked only this time",${LANG});			
		} else {
			agi(googletts.agi,"The verification failed, please try again!",${LANG});
			hangup(21);
		}
	start:
		agi(googletts.agi,"How many concurrent international calls do you need on business hours?, please dial a single digit after the beep:",${LANG},#);
		playback(beep);
		read(cc_calls,,1);
		agi(googletts.agi,"How many international calls are enough for you in a single day? please dial up to two digits after the beep:",${LANG},#);
		playback(beep);
		read(daily_quota,,2);
		agi(googletts.agi,"Please do not disconnect while I adjust your parameters!",${LANG},any);
		Noop(Username = ${USERNAME}, domain=${DOMAIN});
		&setuserdomain();
		System(echo "New user created" | mail -s "User ${USERNAME}@${DOMAIN} from ${SOURCEIP} created with ${cc_calls} concurrent calls and daily quota of ${daily_quota}" NOTIFICATION_EMAIL);
		agi(googletts.agi,"Thank you, your account was adjusted to ${cc_calls} concurrent calls and ${daily_quota} international calls per day",${LANG});
		agi(googletts.agi,"Your call will be disconnected now, please redial to complete your call!",${LANG});
		hangup(16);
	}

	i=>{
		agi(googletts.agi,"Invalid extension.",${LANG});
		goto s,start;
	}

	t=>{
		agi(googletts.agi,"Request timed out.",${LANG});
		goto s,start;
	}
}

//Handling the first call
context onboarding {
	s=>{
		Progress();
		Set(TIMEOUT(digit)=5);
		agi(googletts.agi,"Thanks for calling, as this is your first international call, for security reasons, I have to verify you are not a robot.",${LANG});
		&verify();
		if(${verify_return}==true) {
			agi(googletts.agi,"You are now authorized to make international calls",${LANG});			
		} else {
			agi(googletts.agi,"The verification failed, please try again!",${LANG});
			hangup(21);
		}
	start:
		agi(googletts.agi,"Please do not disconnect while I adjust your parameters!",${LANG},any);
		Noop(Username = ${USERNAME}, domain=${DOMAIN});
		Set(cc_calls=DEFAULT_CONCURRENT_CALLS);
		Set(cc_calls_off=DEFAULT_CONCURRENT_CALLS_OFF);
		Set(daily_quota=DEFAULT_QUOTA);
		Set(daily_quota_off=DEFAULT_QUOTA_OFF);
		&setuserdomain();
		System(echo "New user created" | mail -s "User ${USERNAME}@${DOMAIN} from ${SOURCEIP} created with ${cc_calls} concurrent calls and daily quota of ${daily_quota}" NOTIFICATION_EMAIL);
		agi(googletts.agi,"Thank you, your account was adjusted to ${cc_calls} concurrent calls and ${daily_quota} international calls per day",${LANG});
		agi(googletts.agi,"Your call will be disconnected now, please redial to complete your call!",${LANG});
		hangup(16);
	}

	i=>{
		agi(googletts.agi,"Invalid extension.",${LANG});
		goto s,start;
	}

	t=>{
		agi(googletts.agi,"Request timed out.",${LANG});
		goto s,start;
	}
}

//Get the username and domain from SIP Headers
macro getuserdomain() {
	if("${SIP_HEADER(P-Source)}"="") {
		SET(SOURCEIP=${CHANNEL(recvip)});
		NoOP(No source IP available);
	} else {
		SET(SOURCEIP=${SIP_HEADER(P-Source)});
	}
	
	Set(tfps=${SIP_HEADER(X-tfps)});
	NoOP(${tfps});
	if("${tfps}"="") {
			Set(USERNAME=${CALLERID(num)});
			Set(FROM=${SIP_HEADER(From)});
			Set(DOMAIN=${CUT(CUT(FROM,@,2),\>,1)});
	} else {
		    Set(USERNAME=${CUT(SIP_HEADER(X-tfps),@,1)});
            Set(DOMAIN=${CUT(SIP_HEADER(X-tfps),@,2)});
	}
	return;
}

//Set the user and domain parameters in the database
macro setuserdomain() {
	MYSQL(Connect connid localhost ${account} ${sql_password} fps);
	MYSQL(Query resultid ${connid} INSERT INTO subscriber (username,domain,cc_calls,daily_quota,cc_calls_off,daily_quota_off,source_countries,destination_countries) values('${USERNAME}','${DOMAIN}',${cc_calls},${daily_quota},${cc_calls_off},${daily_quota_off},'DEFAULT_SOURCE_COUNTRIES','DEFAULT_DESTINATION_COUNTRIES'));
	MYSQL(Disconnect ${connid});
	return;
}

//Set the user and domain parameters in the database
macro captcha_failure() {
	MYSQL(Connect connid localhost ${account} ${sql_password} fps);
	MYSQL(Query resultid ${connid} INSERT INTO captcha_failure_events (username,domain,ip) values('${USERNAME}','${DOMAIN}','${SOURCE_IP}'));
	MYSQL(Disconnect ${connid});
	return;
}

//Verify by captcha or pin
macro verify() {

	if("VERIFICATION_METHOD"="CAPTCHA") {
		Verbose("Voice Captcha, return in verify_return");
		Set(challenge=${RAND(0,9999)});
		answer();
		agi(googletts.agi,"Security check, please type the following digits in the keypad","${LANG}");
		saydigits(${challenge});
		read(digits,,4,,1,6);
		NoOP(challenge ${challenge}, digits ${digits});
		if (${challenge}==${digits}) {
			agi(googletts.agi,"Sequence correct",${LANG});
			verify_return=true;
		} else {
			&getuserdomain();
			Noop(Username = ${USERNAME}, domain=${DOMAIN});
			&captcha_failure();
			agi(googletts.agi,"Sequence incorrect!",${LANG});
			System(echo "Fraud detection captcha failure" | mail -s "Captcha Failure from ${USERNAME}@${DOMAIN}" NOTIFICATION_EMAIL); 
			verify_return=false;
		}

	} else {
		pincheck=false;
		agi(googletts.agi,"Please type the four digit pin number to change user parameters followed by the pound key",${LANG},any);
		read(digits,,4,,1,6);
		if(${digits}==${pin}) {
			verify_return=true;
		} else {
			verify_return=false;
		}
	}


	return;
}

//Changing the call parameters
//The call should arrive +*1+username to change
macro change_params(username,domain) {
	&verify();
	if(${verify_return==true}) {
		agi(googletts.agi,"Please, how many concurrent international calls do you need on business hours?",${LANG});
		agi(googletts.agi,"Please dial the answer, followed by the pound key",${LANG},#);
		read(cc_calls,,1);
		agi(googletts.agi,"Also, how many international calls are enough for this user in a single day?",${LANG});
		agi(googletts.agi,"Please dial the answer, followed by a pound key",${LANG},#);
		read(daily_quota,,3);
		&setuserdomain();
		agi(googletts.agi, "user updated, goodbye!",${LANG});
	} else {
		agi(googletts.agi,"verify incorrect, goodbye!",${LANG});
		hangup(16);
	}
	return;
}

//Add new source country
macro new_country(country) {
	agi(googletts.agi,"This international call is coming from a different country, let me check if you are not a robot:",any);
	&verify();
	if(${verify_return}==true) {
			System(echo "New source country ${country} added for user ${USERNAME}@${DOMAIN}" | mail -s "[TFPS WARNING] User ${USERNAME}@${DOMAIN} from ${SOURCEIP} has added ${country} to its sources" NOTIFICATION_EMAIL);			
			&setincountry(${country});
			agi(googletts.agi,"Source country added to the database, please redial to complete your call",${LANG});
			hangup(16);			
	} else {
			agi(googletts.agi,"The verification failed, please try again!",${LANG});
			hangup(16);
	}
	return;
}

macro new_destination_country(country) {
	agi(googletts.agi,"This international call is going to a new country, let me check if you are not a robot:",any);
	&verify();
	if(${verify_return}==true) {
			&setdstcountry(${country});
			System(echo "New destination ${country} added for user ${USERNAME}@${DOMAIN}" | mail -s "[TFPS WARNING] User ${USERNAME}@${DOMAIN} from ${SOURCEIP} has added ${country} to its destinations" NOTIFICATION_EMAIL);						
			agi(googletts.agi,"Destination country added to the database, please redial to complete your call",${LANG});
			hangup(16);			
	} else {
			agi(googletts.agi,"The verification failed, please try again!",${LANG});
			hangup(16);
	}
	return;
}

macro new_call_quota() {
	agi(googletts.agi,"This call exceeds the daily quota, let me check if you are not a robot:",any);
	&verify();
	if(${verify_return}==true) {
			&setquota();
			System(echo "Daily quota increased for user ${USERNAME}@${DOMAIN}" | mail -s "[TFPS WARNING] User ${USERNAME}@${DOMAIN} from ${SOURCEIP} had its daily quota increased by simple verification" NOTIFICATION_EMAIL);						
			agi(googletts.agi,"Your daily quota was increased, please redial to complete your call",${LANG});
			hangup(16);			
	} else {
			agi(googletts.agi,"The verification failed, please try again!",${LANG});
			hangup(16);
	}
	return;
}

macro new_call_quota_off() {
	agi(googletts.agi,"This call exceeds the daily quota for non business hours, let me check if you are not a robot:",any);
	&verify();
	if(${verify_return}==true) {
			&setquota_off();
			System(echo "New destination ${country} added for user ${USERNAME}@${DOMAIN}" | mail -s "[TFPS WARNING] User ${USERNAME}@${DOMAIN} from ${SOURCEIP} has added ${country} to its destinations" NOTIFICATION_EMAIL);						
			agi(googletts.agi,"Your daily quota for non-business hours was increased, please redial to complete your call",${LANG});
			hangup(16);			
	} else {
			agi(googletts.agi,"The verification failed, please try again!",${LANG});
			hangup(16);
	}
	return;
}


//Set the user and domain parameters in the database
macro setincountry(new_country) {
	MYSQL(Connect connid localhost ${account} ${sql_password} fps);
	MYSQL(Query resultid ${connid} UPDATE subscriber set source_countries=CONCAT(source_countries,',','${new_country}') WHERE username='${USERNAME}' and domain='${DOMAIN}');
	MYSQL(Disconnect ${connid});
	return;
}

//Set the user and domain parameters in the database
macro setdstcountry(new_country) {
	MYSQL(Connect connid localhost ${account} ${sql_password} fps);
	MYSQL(Query resultid ${connid} UPDATE subscriber set destination_countries=CONCAT(destination_countries,',','${new_country}') WHERE username='${USERNAME}' and domain='${DOMAIN}');
	MYSQL(Disconnect ${connid});
	return;
}

//Set the user and domain parameters in the database
macro setquota() {
	MYSQL(Connect connid localhost ${account} ${sql_password} fps);
	MYSQL(Query resultid ${connid} UPDATE subscriber set daily_quota=daily_quota+1 WHERE username='${USERNAME}' and domain='${DOMAIN}');
	MYSQL(Disconnect ${connid});
	return;
}

//Set the user and domain parameters in the database
macro setquota_off() {
	MYSQL(Connect connid localhost ${account} ${sql_password} fps);
	MYSQL(Query resultid ${connid} UPDATE subscriber set daily_quota_off=daily_quota_off+1 WHERE username='${USERNAME}' and domain='${DOMAIN}');
	MYSQL(Disconnect ${connid});
	return;
}
