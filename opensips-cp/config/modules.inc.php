<?php
/*
 * Copyright (C) 2011 OpenSIPS Project
 *
 * This file is part of opensips-cp, a free Web Control Panel Application for 
 * OpenSIPS SIP server.
 *
 * opensips-cp is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips-cp is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */


### List with all the available modules - you can enable and disable module from here

$config_admin_modules = array (
	"list_admins"	=> array (
		"enabled"	=> true,
		"name"		=> "Access"
	),
	"boxes_config"    => array (
		"enabled"   => true,
		"name"		=> "Boxes"
	)
);

$config_modules 	= array (
	"users"			=> array (
		"enabled" 	=> true,
		"name" 		=> "Users",
		"icon"		=> "images/icon-user.svg",
		"modules"	=> array (
			"user_management"	=> array (
				"enabled"		=> true,
				"name"			=> "User Management"
			),
			"alias_management"	=> array (
				"enabled"		=> false,
				"name"			=> "Alias Management"
			),
			"group_management"	=> array (
				"enabled"		=> false,
				"name"			=> "Group Management"
			),
		)
	),
	"system"		=> array (
		"enabled"	=> true,
		"name"		=> "System",
		"icon"		=> "images/icon-system.svg",
		"modules"	=> array (
			"addresses"			=> array (
				"enabled"		=> true,
				"name"			=> "IP Blacklist"
			),
			"callcenter"		=> array (
				"enabled"		=> false,
				"name"			=> "Callcenter"
			),
			"cdrviewer"			=> array (
				"enabled"		=> true,
				"name"			=> "CDR Viewer"
			),
			"dialog"			=> array (
				"enabled"		=> false,
				"name"			=> "Dialog"
			),
			"dialplan"			=> array (
				"enabled"		=> true,
				"name"			=> "UA Blacklist"
			),
			"dispatcher"			=> array (
				"enabled"		=> false,
				"name"			=> "Dispatcher"
			),
			"domains"			=> array (
				"enabled"		=> true,
				"name"			=> "Domains"
			),
			"drouting"			=> array (
				"enabled"		=> true,
				"name"			=> "Country Prefixes"
			),
			"clusterer"			=> array (
				"enabled"		=> false,
				"name"			=> "Clusterer"
			),
			"loadbalancer"			=> array (
				"enabled"		=> false,
				"name"			=> "Load Balancer"
			),
			"mi"				=> array (
				"enabled"		=> true,
				"name"			=> "MI Commands"
			),
			"monit"				=> array (
				"enabled"		=> false,
				"name"			=> "Monit"
			),
			"rtpproxy"			=> array (
				"enabled"		=> false,
				"name"			=> "RTPProxy"
			),
			"rtpengine"			=> array (
				"enabled"		=> false,
				"name"			=> "RTPEngine"
			),
			"siptrace"			=> array (
				"enabled"		=> false,
				"name"			=> "SIP Trace"
			),
			"smonitor"			=> array (
				"enabled"		=> true,
				"name"			=> "Statistics Monitor"
			),
			"tls_mgm"			=> array (
				"enabled"		=> false,
				"name"			=> "TLS Management"
			),
			"uac_registrant"		=> array (
				"enabled"		=> false,
				"name"			=> "UAC Registrant"
			),
			"smpp"				=> array (
				"enabled"		=> false,
				"name"			=> "SMPP Gateway"
			),
		)
	),
);




?>
