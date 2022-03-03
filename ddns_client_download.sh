#!/bin/sh 
# ###################################
# ssl enabled ddns dynu.com client for rooted TOON ONLY. 
# by Gerlag
# use at your own risk
# ###################################
# format conf file ddns_client.conf : 
# line 1: #remark 
# line 2: password of dynu in plain text
# line 3: username of dynu in plain text
# line 4: domainname at dynu.com in plain text
# line 5: external port (default 443)
# ###################################
# Online install: 
# wget -O dds_client_download.sh https://raw.githubusercontent.com/gerlag/ddns_for_toon/main/ddns_client_download.sh && sh ddns_client_download.sh install
# or 
# curl https://raw.githubusercontent.com/gerlag/ddns_for_toon/main/ddns_client_download.sh -O && sh ddns_client_download.sh install
# or 
# download ddns_client_download.sh manually, upload to Toon /root/ e.g. with winscp and execute in terminal sh /root/ddns_client_download.sh install
conffile="/root/.ddns_client.sh/ddns_client.conf"
conffile_acme="/root/.acme.sh/account.conf"
authfile_lighttpd="/HCBv2/etc/lighttpd/lighttpd.user"
croncmd="/root/ddns_client.sh  > /dev/null 2>&1"
cronjob="*/59 * * * * $croncmd" # at every 59th minute
croncmd_at_boot="/root/ddns_client.sh reload  > /dev/null 2>&1"
cronjob_at_boot="@reboot sleep 5 && $croncmd_at_boot"


echo SSL enabled ddns dynu.com client for rooted TOON ONLY.

# ###################################
# Move (downloaded) script to [hidden] directory, this keeps root directory decent
# ###################################
 
mkdir -p /root/.ddns_client.sh
SCRIPT=$(readlink -f "$0")
echo $SCRIPT

if [ $SCRIPT = "/root/ddns_client_download.sh" ]; then
	mv /root/ddns_client_download.sh /root/.ddns_client.sh/ddns_client.sh
	chmod a+x /root/.ddns_client.sh/ddns_client.sh
fi 
ln -s /root/.ddns_client.sh/ddns_client.sh /root/ddns_client.sh
cd /root/.ddns_client.sh


# ###################################
# Function(s)
# ###################################

supply_credentials(){
confident=n
while [ $confident != y ]
  do 
    read -t 60 -r -p  "Enter username of your Dynu.com account:  " username
	read -t 60 -r -p  "Enter password of your Dynu.com account:  " password
	read -t 60 -r -p  "Enter domain name of this TOON in Dynu.com account:  " domain
	read -t 60 -r -p  "Enter external open port to Toon in router : [443]  " external_port
	if [ $external_port ="" ]; then
		external_port=443
	fi
	echo You entered: 	
	echo 'username: '$username 
	echo 'password: '$password 
	echo 'domain  : '$domain 
	echo 'ext port: '$external_port 
	read -t 60 -r -p  "Are you confident with that: y/N " confident
	confident=$(echo -n "$confident" | tr '[:upper:]' '[:lower:]')
 done
  	echo "#dynu" > $conffile
	echo $password >> $conffile
	echo $username >> $conffile
	echo $domain >> $conffile
	echo $external_port >> $conffile
}


supply_credentials_acme(){
while [ $confident != y ]
  do 
	read -t 60 -r -p  "Enter e-mail address to send SSL renewal alerts to:  " email
	read -t 60 -r -p  "Dynu_ClientId: " Dynu_ClientId
	read -t 60 -r -p  "Dynu_Secret: " Dynu_Secret
	echo You entered: 	
	echo 'email         : '$email 
	echo 'Dynu_ClientId : '$Dynu_ClientId 
	echo 'Dynu_Secret   : '$Dynu_Secret 
	read -t 60 -r -p  "Are you confident with that: y/N " confident
	confident=$(echo -n "$confident" | tr '[:upper:]' '[:lower:]')
  done
	echo ACCOUNT_EMAIL=\'$email\' > $conffile_acme
	echo Dynu_ClientId=\'$Dynu_ClientId\'>> $conffile_acme
	echo Dynu_Secret=\'$Dynu_Secret\' >> $conffile_acme 
}   

lighttpd_ext_auth_ssl_conf(){
	gateway=$(route -n | grep 'UG[ \t]' | awk '{print $2}')
	network=${gateway%?}0/24
	echo Detected LAN is: 
	echo $network
	FILE=/HCBv2/etc/lighttpd/lighttpd_ext_auth_ssl.conf
	cat > "$FILE" <<EOF
# lighttpd configuration file for rooted toon with exernal authorisation and ssl 
#
# use it as a base for lighttpd 1.0.0 and above
#
# \$Id: lighttpd.conf,v 1.7 2004/11/03 22:26:05 weigon Exp \$

############ Options you really have to take care of ####################

## TOON specific settings: search voor TOON remarks

## modules to load
# at least mod_access and mod_accesslog should be loaded
# all other module should only be loaded if really neccesary
# - saves some time
# - saves memory
include_shell "/qmf/etc/lighttpd/genModules"
#server.modules              = (
##                               "mod_hcb_web", 
#                               "mod_rewrite",
#                               "mod_redirect",
#                               "mod_alias",
##                               "mod_access",
#                               "mod_cml",
#                               "mod_trigger_b4_dl",
##                               "mod_auth",
#                               "mod_status",
#                               "mod_setenv",
#                               "mod_fastcgi",
#                               "mod_proxy",
#                               "mod_simple_vhost",
#                               "mod_evhost",
#                               "mod_userdir",
#                               "mod_cgi",
##                               "mod_compress",
#                               "mod_ssi",
#                               "mod_usertrack",
#                               "mod_expire",
#                               "mod_secdownload",
#                               "mod_rrdtool",
##                               "mod_accesslog" 
##                               "mod_indexfile" 
##                               "mod_staticfile" 
## 				 "mod_dirlisting"
#)

## a static document-root, for virtual-hosting take look at the
## server.virtual-* options
server.document-root        = "/qmf/www"

\$SERVER["socket"] == ":10080" {
server.document-root = "/qmf/www"
}

## TOON specific
#added  GH! 20220224
    \$SERVER["socket"] == ":443" {
    	server.document-root = "/HCBv2/www"
		ssl.engine  = "enable"
    	ssl.pemfile = "/HCBv2/etc/lighttpd/ssl/rooted_toon.pem"
		ssl.ca-file = "/HCBv2/etc/lighttpd/ssl/rooted_toon_ca.cer"
    	ssl.use-sslv2 = "disable" 
    	ssl.use-sslv3 = "disable" 
    	ssl.use-compression = "disable" 
    	ssl.disable-client-renegotiation = "enable" 
        ssl.honor-cipher-order = "enable" 

        # PCI DSS compliant cipher list July/2016 (TLS 1.0 disabled) 
        ssl.cipher-list = "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA" 
    }
## end TOON specific


## where to send error-messages to
server.errorlog             = "/tmp/lighttpd_error.log"

# files to check for if .../ is requested
index-file.names            = ( "index.php", "index.html",
                                "index.htm", "default.htm" )

## set the event-handler (read the performance section in the manual)
# server.event-handler = "freebsd-kqueue" # needed on OS X

# mimetype mapping
mimetype.assign             = (
  ".pdf"          =>      "application/pdf",
  ".sig"          =>      "application/pgp-signature",
  ".spl"          =>      "application/futuresplash",
  ".class"        =>      "application/octet-stream",
  ".ps"           =>      "application/postscript",
  ".torrent"      =>      "application/x-bittorrent",
  ".dvi"          =>      "application/x-dvi",
  ".gz"           =>      "application/x-gzip",
  ".pac"          =>      "application/x-ns-proxy-autoconfig",
  ".swf"          =>      "application/x-shockwave-flash",
  ".tar.gz"       =>      "application/x-tgz",
  ".tgz"          =>      "application/x-tgz",
  ".tar"          =>      "application/x-tar",
  ".zip"          =>      "application/zip",
  ".mp3"          =>      "audio/mpeg",
  ".m3u"          =>      "audio/x-mpegurl",
  ".wma"          =>      "audio/x-ms-wma",
  ".wax"          =>      "audio/x-ms-wax",
  ".ogg"          =>      "application/ogg",
  ".wav"          =>      "audio/x-wav",
  ".gif"          =>      "image/gif",
  ".jar"          =>      "application/x-java-archive",
  ".jpg"          =>      "image/jpeg",
  ".jpeg"         =>      "image/jpeg",
  ".png"          =>      "image/png",
  ".xbm"          =>      "image/x-xbitmap",
  ".xpm"          =>      "image/x-xpixmap",
  ".xwd"          =>      "image/x-xwindowdump",
  ".css"          =>      "text/css",
  ".html"         =>      "text/html",
  ".htm"          =>      "text/html",
  ".js"           =>      "text/javascript",
  ".asc"          =>      "text/plain",
  ".c"            =>      "text/plain",
  ".cpp"          =>      "text/plain",
  ".log"          =>      "text/plain",
  ".conf"         =>      "text/plain",
  ".text"         =>      "text/plain",
  ".txt"          =>      "text/plain",
  ".dtd"          =>      "text/xml",
  ".xml"          =>      "text/xml",
  ".mpeg"         =>      "video/mpeg",
  ".mpg"          =>      "video/mpeg",
  ".mov"          =>      "video/quicktime",
  ".qt"           =>      "video/quicktime",
  ".avi"          =>      "video/x-msvideo",
  ".asf"          =>      "video/x-ms-asf",
  ".asx"          =>      "video/x-ms-asf",
  ".wmv"          =>      "video/x-ms-wmv",
  ".bz2"          =>      "application/x-bzip",
  ".tbz"          =>      "application/x-bzip-compressed-tar",
  ".tar.bz2"      =>      "application/x-bzip-compressed-tar",
  # default mime type
  ""              =>      "application/octet-stream",
 )

# Use the "Content-Type" extended attribute to obtain mime type if possible
#mimetype.use-xattr        = "enable"


## send a different Server: header
## be nice and keep it at lighttpd
# server.tag                 = "lighttpd"

#### accesslog module
accesslog.filename          = "/tmp/lighttpd_access.log"

## deny access the file-extensions
#
# ~    is for backupfiles from vi, emacs, joe, ...
# .inc is often used for code includes which should in general not be part
#      of the document-root
url.access-deny             = ( "~", ".inc" )

#\$HTTP["url"] =~ "\.pdf\$" {
#  server.range-requests = "disable"
#}

##
# which extensions should not be handle via static-file transfer
#
# .php, .pl, .fcgi are most often handled by mod_fastcgi or mod_cgi
static-file.exclude-extensions = ( ".php", ".pl", ".fcgi" )

######### Options that are good to be but not neccesary to be changed #######

## bind to port (default: 80)
server.port                = 80

## bind to localhost (default: all interfaces)
#server.bind                = "127.0.0.1"

## error-handler for status 404
#server.error-handler-404   = "/error-handler.html"
#server.error-handler-404   = "/error-handler.php"

## to help the rc.scripts
#server.pid-file            = "/var/run/lighttpd.pid"


###### virtual hosts
##
##  If you want name-based virtual hosting add the next three settings and load
##  mod_simple_vhost
##
## document-root =
##   virtual-server-root + virtual-server-default-host + virtual-server-docroot
## or
##   virtual-server-root + http-host + virtual-server-docroot
##
#simple-vhost.server-root   = "/srv/www/vhosts/"
#simple-vhost.default-host  = "www.example.org"
#simple-vhost.document-root = "/htdocs/"


##
## Format: <errorfile-prefix><status-code>.html
## -> ..../status-404.html for 'File not found'
#server.errorfile-prefix    = "/usr/share/lighttpd/errors/status-"
#server.errorfile-prefix    = "/srv/www/errors/status-"

## virtual directory listings
#dir-listing.activate       = "enable"
## select encoding for directory listings
#dir-listing.encoding        = "utf-8"

## enable debugging
#debug.log-request-header   = "enable"
#debug.log-response-header  = "enable"
#debug.log-request-handling = "enable"
#debug.log-file-not-found   = "enable"

### only root can use these options
#
# chroot() to directory (default: no chroot() )
#server.chroot              = "/"

## change uid to <uid> (default: don't care)
#server.username            = "wwwrun"

## change uid to <uid> (default: don't care)
#server.groupname           = "wwwrun"

#### dirlisting module
#server.dir-listing = "enable"

#### compress module
compress.cache-dir         = "/tmp/www-cache/"
compress.allowed-encodings = ("gzip")
compress.filetype          = ("text/plain", "text/html", "text/css", "application/octet-stream", "text/javascript", "text/xml", "application/octet-stream")

#### proxy module
## read proxy.txt for more info
#proxy.server               = ( ".php" =>
#                               ( "localhost" =>
#                                 (
#                                   "host" => "192.168.0.101",
#                                   "port" => 80
#                                 )
#                               )
#                             )

#### fastcgi module
## read fastcgi.txt for more info
## for PHP don't forget to set cgi.fix_pathinfo = 1 in the php.ini
#fastcgi.server             = ( ".php" =>
#                               ( "localhost" =>
#                                 (
#                                   "socket" => "/var/run/lighttpd/php-fastcgi.socket",
#                                   "bin-path" => "/usr/local/bin/php-cgi"
#                                 )
#                               )
#                            )

#### CGI module
#cgi.assign                 = ( ".pl"  => "/usr/bin/perl",
#                               ".cgi" => "/usr/bin/perl" )
#

#### SSL engine
#ssl.engine                 = "enable"
#ssl.pemfile                = "/etc/ssl/private/lighttpd.pem"

#### status module
#status.status-url          = "/server-status"
#status.config-url          = "/server-config"

#### auth module
## read authentication.txt for more info
auth.backend               = "plain"
auth.backend.plain.userfile = "/qmf/etc/lighttpd/lighttpd.user"
#auth.backend.plain.groupfile = "lighttpd.group"

#auth.backend.ldap.hostname = "localhost"
#auth.backend.ldap.base-dn  = "dc=my-domain,dc=com"
#auth.backend.ldap.filter   = "(uid=\$)"

## TOON specific
## local IP addreses not behind password
\$HTTP["remoteip"] == "127.0.0.1"{}
else \$HTTP["remoteip"] == "$network" {}# If filling in your TOON's NAT address range, only IP adresses outside LAN have password protection
else \$HTTP["remoteip"] != ""{
auth.require               = ( "" =>
                               ("method" => "basic",
								"realm" => "Voer wachtwoord in",
								"require" => "valid-user" 
                               )
                             )
}
## end TOON specific

#### url handling modules (rewrite, redirect, access)
#url.rewrite                = ( "^/\$"             => "/server-status" )
#url.redirect               = ( "^/wishlist/(.+)" => "http://www.123.org/\$1" )
#### both rewrite/redirect support back reference to regex conditional using %n
#\$HTTP["host"] =~ "^www\.(.*)" {
#  url.redirect            = ( "^/(.*)" => "http://%1/\$1" )
#}

#
# define a pattern for the host url finding
# %% => % sign
# %0 => domain name + tld
# %1 => tld
# %2 => domain name without tld
# %3 => subdomain 1 name
# %4 => subdomain 2 name
#
#evhost.path-pattern        = "/srv/www/vhosts/%3/htdocs/"

#### expire module
#expire.url                 = ( "/buggy/" => "access 2 hours", "/asdhas/" => "access plus 1 seconds 2 minutes")

#### ssi
#ssi.extension              = ( ".shtml" )

#### rrdtool
#rrdtool.binary             = "/usr/bin/rrdtool"
#rrdtool.db-name            = "/var/lib/lighttpd/lighttpd.rrd"

#### setenv
#setenv.add-request-header  = ( "TRAV_ENV" => "mysql://user@host/db" )
#setenv.add-response-header = ( "X-Secret-Message" => "42" )

## for mod_trigger_b4_dl
# trigger-before-download.gdbm-filename = "/var/lib/lighttpd/trigger.db"
# trigger-before-download.memcache-hosts = ( "127.0.0.1:11211" )
# trigger-before-download.trigger-url = "^/trigger/"
# trigger-before-download.download-url = "^/download/"
# trigger-before-download.deny-url = "http://127.0.0.1/index.html"
# trigger-before-download.trigger-timeout = 10

## for mod_cml
## don't forget to add index.cml to server.indexfiles
# cml.extension               = ".cml"
# cml.memcache-hosts          = ( "127.0.0.1:11211" )

#### variable usage:
## variable name without "." is auto prefixed by "var." and becomes "var.bar"
#bar = 1
#var.mystring = "foo"

## integer add
#bar += 1
## string concat, with integer cast as string, result: "www.foo1.com"
#server.name = "www." + mystring + var.bar + ".com"
## array merge
#index-file.names = (foo + ".php") + index-file.names
#index-file.names += (foo + ".php")

#### include
#include /etc/lighttpd/lighttpd-inc.conf
## same as above if you run: "lighttpd -f /etc/lighttpd/lighttpd.conf"
#include "lighttpd-inc.conf"

#### include_shell
#include_shell "echo var.a=1"
## the above is same as:
#var.a=1
   
EOF
		
}

update_mobile_web(){
	# replace the below texts because the originals are wrong. 
	sed -i 's/Zon opbrengst vandaag/Zon opbrengst gisteren/' /HCBv2/www/mobile/index.html
	sed -i 's/Elektra productie nu/Elektra teruglevering nu/' /HCBv2/www/mobile/index.html
}

# ###################################
# END Function(s)
# ###################################

# ####################################
# first check if wget is installed and has https
# ####################################

wget https:// 1>/dev/null 2>/tmp/wget_err_stdout
ERROR=$( cat /tmp/wget_err_stdout )
	if [ "$ERROR" = 'https://: HTTPS support not compiled in.' ]; then
		https='0';
		echo no https in wget
	else
		https='1';
		echo https in wget
	fi


# ####################################
# need for installing or uninstalling?
# ####################################

# check for argument, if this is install, then add credentails, add cron and job, try to install wget with https and create lighttpd.conf with ssl enabled and external authorisation. 
if [ $# -eq 1 ];  then # argu,mrt suplied
	if [ "$1"  == "uninstall" ]; then
		echo Uninstall catched 
		echo uninstall, removing cron job and acme.sh. That\'s all I will do. 
		( crontab -l | grep -v -F "$croncmd" ) | crontab -
		( crontab -l | grep -v -F "$croncmd_at_boot" ) | crontab -
		/root/.acme.sh/acme.sh --uninstall 
		echo you can manually close port 443 in firewall, but it doesný hurt to let it open.
		echo you can manually revert lighttp.conf from $BACKUPOFINITIALFOUNDFILE but it doesný hurt to let it as is.
		echo Restarting lighttpd 
		kill $(pidof lighttpd) # this is very Toon specific I assume... 
		sleep 5 
		echo dynu ddns uninstalled
		exit 0 
		
	elif [ "$1"  == "install" ] || [ "$1"  == "reload" ]; then
		echo install or reload catched  
		echo installing ddns client or reloading configuration. 
		echo Remark: You can uninstall this script by using \"uninstall\" as argument   

		# ####################################
		# install  ###########################
		# ####################################



		if [ $( ! which wget >/dev/null ) ] || [  "$https" = '0' ]; then
			echo wget, preferably with https support,  is needed but not yet installed. 
				read -t 60 -r -p  "Shall I try to install wget-https for you at your own risk?  [y/N] " response
			if [ "$response" != "${response#[Yy]}" ] ;then # this grammar (the #[] operator) means that the variable $answer where any Y or y in 1st position will be dropped if they exist.
					echo You choose to  have wget-https installed by me. Downloading and installing...
				opkg remove wget --force-depends
				opkg install "http://files.domoticaforum.eu/uploads/Toon/ipk/qb2/wget_1.12-r8.2_qb2.ipk" 
			else
				echo 'You choose to not have wget installed by me. You have to install it yourself and then REDO FROM START. "( a la PET 2001 :) )"'
				exit 2
			fi
		fi

		# ####################################
		# check if crontab is installed  
		# ####################################
		if ! which cron> /dev/null ; then	
			echo CRON not yet installed.  
			read -t 60 -r -p  "Shall I try to install CRON for you at your own risk? [y/N] " response
			if [ "$response" != "${response#[Yy]}" ] ;then # this grammar (the #[] operator) means that the variable $answer where any Y or y in 1st position will be dropped if they exist.
					echo You choose to  have cron installed by me. Downloading and installing... 
				sh update-rooted.sh -o
				opkg update
				opkg install cron
				echo rebooting
				echo log in after system restart and run script again.
				reboot -r now
				exit 
			else
				echo You choose to not have cron installed by me. You have to install it yourself and then REDO FROM START. "(PET 2001)"
				exit 2
			fi
		fi

		# ####################################
		# create crontab job if not already set 
		# ####################################

		# first: create root crontab is not there. this eliminates 'no crontab for root'. 
		# https://stackoverflow.com/questions/19598482/how-to-disable-no-crontab-for-user-message-in-shell
		touch /var/cron/tabs/root
		chmod 600 /var/cron/tabs/root
		chown root:root /var/cron/tabs/root

		if ! crontab -l | grep -q "$croncmd"; then 
			echo "Cronjob doesn't exist yet, so first creating cronjob $croncmd"  
			# entry cron om the fly, 
			# inspiration from
			# https://stackoverflow.com/questions/878600/how-to-create-a-cron-job-using-bash-automatically-without-the-interactive-editor
			# add to crontab, this method it is immune to multiple insertions
			( crontab -l | grep -v -F "$croncmd" ; echo "$cronjob" ) | crontab -
		fi
		
		if ! crontab -l | grep -q "$croncmd_at_boot"; then 
			echo "Cronjob at boot  doesn't exist yet, so first creating cronjob $croncmd_at_boot"  
			# entry cron om the fly, 
			# inspiration from
			# https://stackoverflow.com/questions/878600/how-to-create-a-cron-job-using-bash-automatically-without-the-interactive-editor
			# add to crontab, this method it is immune to multiple insertions
			( crontab -l | grep -v -F "$croncmd_at_boot" ; echo "$cronjob_at_boot" ) | crontab -
		fi
		
		
		# ####################################
		# create conf file with external auth and ssl-anabled. 
		# ####################################
		lighttpd_ext_auth_ssl_conf
		
		# ####################################
		# create self signed SSL test certificate for ssl enabled lighttpd
		# ####################################
		if [ ! -f "/HCBv2/etc/lighttpd/ssl/rooted_toon.pem" ]; then
			mkdir -p /HCBv2/etc/lighttpd/ssl
			echo Creating self signed SSL test certificate for ssl enabled lighttpd
			openssl req -new -x509 -keyout /HCBv2/etc/lighttpd/ssl/rooted_toon.pem -out /HCBv2/etc/lighttpd/ssl/rooted_toon.pem -days 365 -nodes -subj "/C=NL/ST=PROV/L=AMSTERDAM/O=toon/OU=rooted/CN=gerlag/emailAddress=none@none.none"
		else 
			echo SSL certificate already in place, not creating self signed one
		fi 
		
		# ####################################
		# create generate a suficiently stronger DHE parameter
		# ####################################
		if [ ! -f "/etc/ssl/certs/dhparam.pem" ]; then
			echo generate a suficiently strong DHE parameter
			# openssl dhparam -out /etc/ssl/certs/dhparam.pem 4096 
			openssl dhparam -dsaparam -out /etc/ssl/certs/dhparam.pem 2048 # much faster
		else 
			echo dhparam.pem found, not generating new one
		fi 
		
		
		
		# ####################################
		# Create backup of initialy found lighttpd.conf
		# ####################################
		
		INITIALFOUNDFILE=/HCBv2/etc/lighttpd/lighttpd.conf
		BACKUPOFINITIALFOUNDFILE=/HCBv2/etc/lighttpd/lighttpd_backup_pre_ssl_externalauth.conf
		EXTAUTSSLFILE=/HCBv2/etc/lighttpd/lighttpd_ext_auth_ssl.conf
		CONFFILETOBELOADED=/HCBv2/etc/lighttpd/lighttpd.conf
		
		if [ ! -f "$BACKUPOFINITIALFOUNDFILE" ]; then
			echo backing up initial found lightpd config file
			cp $INITIALFOUNDFILE $BACKUPOFINITIALFOUNDFILE
		fi
		
		# ####################################
		#  Copy newly constructed  lighttpd config file to running location
		# ####################################
		echo Copy newly constructed lighttpd config file to running location 
		cp $EXTAUTSSLFILE $CONFFILETOBELOADED
		
		# ####################################
		# Alter some wrong texts of mobile web
		# ####################################
		echo Alter some wrong texts of mobile web page
		update_mobile_web
				
		# ####################################
		# Restart lighttpd
		# ####################################
		
		echo lighttpd is running as process ID: $(pidof lighttpd)
		echo Restarting lighttpd 
		kill $(pidof lighttpd) # this is very Toon specific I assume... 
		sleep 10
		echo lighttpd is now running as process ID: $(pidof lighttpd) 
		
		if [  "$1"  == "reload" ]; then
			exit 0
		fi
		
		# ####################################
		# Open SSL port 443 if not open already . 
		# ####################################		
					
		if [ ! "$(iptables -nL | grep 443)" ]; then 
			echo Open SSL port 443 in firewall
			echo makeing backup of existing iptables
			iptables-save > IPtablesbackup_made_by_ddns_client_sh.txt
			echo find first occurance '-A HCB-INPUT'  in IPtables of 
			line_ip=$( iptables -L -n --line-numbers | grep -m 1 'tcp dpt:22' | awk '{print $1;}')
			echo Open SSL port 443 in firewall
			iptables -I HCB-INPUT $line_ip -p tcp -m tcp --dport 443 --tcp-flags SYN,RST,ACK SYN -j ACCEPT
			echo save new iptablesd in IPtables_443_open.txt
			iptables-save > IPtables_443_open.txt
			echo copy the just saved iptables to iptables.conf to make it permanent
			cp IPtables_443_open.txt /etc/default/iptables.conf
			echo restart iptables
			/etc/init.d/iptables restart
			cat /etc/default/iptables.conf # debug
		fi
			
		# ####################################
		# supply credentials of dynu.com
		# ####################################		
					
		confident=n
		if [  -f "$conffile" ]; then
			echo Dynu configuration file found with content: 
			echo '(Password /  Username / DDNS domain)' 	
			cat $conffile
			read -t 60 -r -p  "Are you confident with that: y/N " confident
			confident=$(echo -n "$confident" | tr '[:upper:]' '[:lower:]')
		fi  
		if [ $confident != 'y' ]; then 
			supply_credentials # credentials of dynu.com
		fi

		
		# ####################################
		# Install acme.sh  
		# ####################################
		echo installing acme
		sleep 5
		mkdir acme_temp
		cd acme_temp
		wget -O -  http://get.acme.sh | sh -s email=$email
		sleep 5
		confident=n
		if [  -f "$conffile_acme" ]; then
			echo Acme configuration file found with content: 	
			cat $conffile_acme
			read -t 60 -r -p  "Are you confident with that: y/N " confident
			confident=$(echo -n "$confident" | tr '[:upper:]' '[:lower:]')
		fi 
		if [ $confident != 'y' ]; then 
			supply_credentials_acme
		fi
		domain=$(head -4 $conffile | tail -1 | tr -d '\r\n')
		external_port=:$(head -5 $conffile | tail -1 | tr -d '\r\n')
		echo "domain: $domain"
		echo "external_port: $external_port"
		if [ $external_port = ":443" ];  then
			external_port='';
		fi
		sleep 3
		echo Creating letsencrypt certificate
		/root/.acme.sh/acme.sh --debug --server  letsencrypt --issue --fullchain-file /HCBv2/etc/lighttpd/ssl/rooted_toon.pem  --key-file  /HCBv2/etc/lighttpd/ssl/rooted_toon.key --dns dns_dynu -d $domain --reloadcmd "cat /HCBv2/etc/lighttpd/ssl/rooted_toon.key >> /HCBv2/etc/lighttpd/ssl/rooted_toon.pem; kill $(pidof lighttpd)" 
		sleep 2
		cat /root/.acme.sh/$domain/ca.cer >> /HCBv2/etc/lighttpd/ssl/rooted_toon_ca.cer
		cd ..
		rm -r acme_temp/	
		echo Instalation completed
		credents=$(cat $authfile_lighttpd) 
		CYAN='\036[0;31m' 
		NC='\033[0m' # No Color
		echo -e Acces of your rooted toon:${CYAN} https://$credents@$domain$external_port/mobile ${NC}
		echo Enjoy! 
		# ####################################
		# END installing  
		# ####################################

	
		# ####################################
		# need for uninstalling?  
		# ####################################

			
	else
		# ####################################
		# non understood argument  
		# ####################################
		echo Use \"install\" , \"reload\" or \"uninstall\" as argument 
		exit 0 
	fi
fi


# ####################################
# get user/password form config file  
# ####################################
 
password=$(head -2 $conffile | tail -1 | tr -d '\r\n')
user=$(head -3 $conffile | tail -1 | tr -d '\r\n')
domain=$(head -4 $conffile | tail -1 | tr -d '\r\n')
external_port=$(head -5 $conffile | tail -1 | tr -d '\r\n')

if [ "$password" == "" ]; then
	echo No conf file or password present.
	echo If not already done, create an account at https://www.dynu.com
	echo and supply the credentials below.
	supply_credentials
	echo Start this script again. 
	exit 1
fi

# ####################################
# update DDNS of dynu.com
# ####################################

token=$(echo -n $password  | md5sum | awk '{print $1}')

if [ "$https" = '1' ]; then 
	wget --no-check-certificate -qO ddns_status.txt  "https://api.dynu.com/nic/update?hostname=$domain\&username=$user\&password=$token" > /dev/null 2>&1
else 
	wget -qO ddns_status.txt  "http://api.dynu.com/nic/update?hostname=$domain\&username=$user\&password=$token" > /dev/null 2>&1
fi
 result=$?
 echo UpdateResult: $result
if [ "$result" != 0  ] ; then 
	echo connection error update check at dynu.com
	exit 1
elif [ "$( cat "ddns_status.txt" )" = 'badauth' ]; then
	echo Wrong authorisation or domain name.
	echo If not already done, create an account at https://www.dynu.com
	echo and supply the credentials below.
	supply_credentials
	echo Start this script again. 
	exit 1
fi  
	echo " "`date` >> ddns_status.txt
	echo ddns result: $(cat ddns_status.txt)
exit 0 
