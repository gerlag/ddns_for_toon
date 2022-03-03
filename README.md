# ddns_for_toon
ddn_client.sh

This script will install a dyndns client for dynu.com and it installs also acme for installing and updating letsencrypt SSL certifcates.  

As a result you'll get external password protected SSL (mobile) access for rooted Toon on a -always free- dynu ddns domain. 

If not already installed, crontab and/or ssl-anabled wget will be installed. 
Some cron tasks will be added, all files will be put in root/.ddn_client.sh/ and root/.acme.sh/

Disclaimer: This howto is only valid for rooted toon and on your own risk
Tested on Toon1 

Howto:
1) Specify username and pasword in Toon for mobile access. 
In Toon go to instellingen => TSC => Mobile login and enter a user name en password and store it. These are the credentials that are needed for external access. After the script is being installed, no credentials are needed is you are in the same LAN as your TOON.  

2) Create an account on dynu.com and register one of their free third level ddns domains
You have to make a notition of:
- username of Dynu.com
- password of dynu.com
- Client ID of your Dynu account (https://www.dynu.com/en-US/ControlPanel/APICredentials) 
- Secret of your dynu account. (https://www.dynu.com/en-US/ControlPanel/APICredentials )
- the domain you registered at dynu.com
- the email address you want renewal notitions to be send to
 
These valus must be entered during the installation of ddn_client.sh 

3) create a port forwarding rule on your router. 
This is router-specific. Below an example op the Ziggo router 
3.1) Example Ziggo
a)   Ga in het linkermenu naar geavanceerde instellingen -> DHCP -> verbonde apparaten selecteer je Toon, meestal zichtbaar als ENECO 001-#####. Dan in het menu 'Voeg IP-adres reservering toe' eronder klik op 'Voeg reservering toe' Noteer het IP-adres (192.168.178.###) 
 
b) Ga in het linkermenu naar beveiliging -> Poort-forwarding en klik op "Voeg nieuwe regel toe"
	Vul in: 
	Lokaal IP 192.168.178.### ( voor ### neem je hetzelfde getal als onder 1 genoteerd)
	Lokale beginpoort 443
	Lokale eindpoort 443
	Externe beginpoort 443
	Externe eindpoort	443
	Protocol	TCP
	Ingeschakeld Actief
	
4) Install ddn_client.sh 
 
 install online by excecuting 
	wget -O dds_client_download.sh https://raw.githubusercontent.com/gerlag/ddns_for_toon/main/ddns_client_download.sh && sh ddns_client_download.sh install
or 

    curl https://raw.githubusercontent.com/gerlag/ddns_for_toon/main/ddns_client_download.sh -O && sh ddns_client_download.sh install


  install manually by uploading ddn_client_download.sh to /root/ en executing 
	sh /root/ddn_client_download.sh install
	

After installation the exact url of your Toon will be given in the terminal. 
This url can be used as wel from your LAN as externally.
