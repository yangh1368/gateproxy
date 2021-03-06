#!/bin/bash
#####################################################################################
# (c) 2016. Gateproxy.com                                                           #
# Licence: Creative Commons Atribución-NoComercial-CompartirIgual 4.0 Internacional #
# HowTO: https://goo.gl/ZT4LTi                                                      #
# Install: git clone https://github.com/maravento/gateproxy.git                     #
# chmod +x gateproxy/gateproxy.sh && gateproxy/gateproxy.sh                         #
# Available Eng-Spa                                                                 #
#####################################################################################
#
# Language spa-eng
#
lm1=("Avanzado" "Advanced")
lm2=("Por favor responda" "Please Answer")
lm3=("Introduzca" "Enter")
lm4=("Ha introducido correctamente" "You have entered correctly")
lm5=("Desea cambiar" "Do you want to change")
lm6=("Ha introducido" "You have entered")
lm7=("Desea instalar" "Do you want to install")
lm8=("Puede elegir cada uno" "You can choose each")
lm9=("para activar" "to activate")
lm10=("ya esta instalado" "is already installed")
#
cm1=("Asegurese de tener instalado Ubuntu 16.04.x LTS x64" "Be sure to have installed Ubuntu LTS x64 16.04.x")
cm2=("Formato de Net interfaces Correcto" "Net Interfaces Format Correct")
cm3=("Formato de Net Interfaces Incorrecto" "Net Interfaces Format Incorrect")
cm4=("Lista de Net Interfaces detectadas con direcciones MACs" "List of Net Interfaces detected with MACs addresses")
cm5=("Ha terminado la configuracion de Net Interfaces" "You have finished setting up your Net Interfaces")
cm6=("Reinicie su servidor y ejecute nuevamente gateproxy.sh" "Restart your server and run again gateproxy.sh")
cm7=("Gateproxy trabaja con NIC-Ethernet. Si eligió una interfaz WiFi" "Gateproxy works with Ethernet NIC. If you chose a WiFi interface")
cm8=("edite /etc/udev/rules.d/10-network.rules antes de reiniciar su" "edit /etc/udev/rules.d/10-network.rules before restarting your")
cm9=("servidor, y en KERNEL de interfaz WiFi, reemplace: en* por wl*" "server, and KERNEL WiFi interface, replace: in * for wl *")
cm10=("Verifique su conexion a internet y reinicie el script" "Check your internet connection and restart the script")
cm11=("con carpeta compartida" "with shared folder")
cm12=("papelera de reciclaje y auditoria" "recycle bin and audit")
cm13=("Proteccion de puertos usb via udev" "USB ports protection via udev")

test "${LANG:0:2}" == "es"
es=$?

clear
gp=~/gateproxy
# CHECKING SO
function is_xenial(){
is_xenial=`lsb_release -sc | grep xenial`
	if [ "$is_xenial" ]; then
    	echo
	echo "SO OK"
  else
	clear
	echo
	echo
	echo "SO Incorrect. Instalacion Abortada-Installation Aborted"
	echo "${cm1[${es}]}"
	echo
	exit
fi
}
is_xenial

# CHECKING INTERFACES
# MAC ADDRESS/ETH PUBLIC
function is_mac_public(){
	read -p "${lm3[${es}]} MAC eth0 (Internet): " MAC
	if [ "$MAC" ]; then
	sed -i "s/00:00:00:00:00:00/$MAC/g" $gp/10-network.rules
   fi
}

# MAC ADDRESS/ETH LOCAL
function is_mac_local(){
	read -p "${lm3[${es}]} MAC eth1 (Localnet): " MAC
	if [ "$MAC" ]; then
	sed -i "s/11:11:11:11:11:11/$MAC/g" $gp/10-network.rules
   fi
}

function is_interfaces(){
is_interfaces=`ifconfig | grep eth`
	if [ "$is_interfaces" ]; then
	echo
	echo "${cm2[${es}]}"
  else
	echo
	echo "${cm3[${es}]}"
	echo "${cm4[${es}]}:"
	echo
	ifconfig | grep HW
	echo
	is_mac_public
	is_mac_local
	sudo cp $gp/10-network.rules /etc/udev/rules.d/10-network.rules
	clear
	echo	
	echo "${cm5[${es}]}"
	echo "${cm6[${es}]}"
	echo
	echo "Importante - Important:"
	echo "${cm7[${es}]}"
	echo "${cm8[${es}]}"
	echo "${cm9[${es}]}"
	echo
	exit 
  fi
}
is_interfaces

clear
echo
echo "    Bienvenido a la instalacion de GateProxy Server v1.0"
echo "        Welcome to installing GateProxy Server v1.0     "
echo
echo "  Requisitos Mínimos / Minimum requirements:"
echo "  GNU/Linux:    Ubuntu 16.04.x LTS x64"
echo "  Processor:    Intel compatible 1x GHz"
echo "  Interfaces:   eth0, eth1"
echo "  RAM:          4GB"
echo "  DD:           200 GB"
echo "  Internet:     High Speed"
echo "  Desktop:      Mate (optional)"
echo "  Dependencies: sudo apt-get -y install git apt dpkg"
echo
echo "  Exención de responsabilidad / Disclaimer:
  Este script puede dañar su sistema si se usa incorrectamente
  Para mayor información, visite gateproxy.com y lea el HowTO
  This script can damage your system if used incorrectly
  For more information, visit gateproxy.com and read the HowTO"
echo
echo "  Presione ENTER para iniciar o CTRL+C para cancelar
  Press ENTER to start or CTRL+C to cancel";
read RES
clear
echo
echo "Checking sum..."
a=$(md5sum $gp/gateproxy.tar.gz | awk '{print $1}')
b=$(cat $gp/gateproxy.md5 | awk '{print $1}')
	if [ "$a" = "$b" ]
  then 
   	echo "sum ok"
   	tar -C gateproxy -xvzf $gp/gateproxy.tar.gz >/dev/null 2>&1 && sleep 2
   	sudo mkdir -p /etc/acl 2>&1
   	sudo cp -rf $gp/acl/* /etc/acl >/dev/null 2>&1 && sleep 2
   	echo OK
  else
   	echo "Bad sum. Abort"
   	echo "${cm10[${es}]}"
   	rm -rf gateproxy*
	exit
fi

# sincronizando hora - synchronized time and backup crontab, source.list
	sudo hwclock -w >/dev/null 2>&1
	sudo cp /etc/crontab{,.bak} >/dev/null 2>&1
	sudo crontab /etc/crontab >/dev/null 2>&1
	sudo cp /etc/apt/sources.list{,.bak} >/dev/null 2>&1
	sudo touch /var/log/alert.log

# CAMBIANDO NOMBRE DE SERVIDOR EN LOS ARCHIVOS DE CONFIGURACION
# CHANGING SERVER NAME IN THE CONFIG FILES
function is_hostname(){
	is_name=`echo $HOSTNAME`
	if [ "$is_name" ]; then
	find $gp/conf -type f -print0 | xargs -0 -I "{}" sed -i "s:gateproxy:$is_name:g"  "{}"
   fi
}
is_hostname

# CAMBIANDO NOMBRE DE LA CUENTA DE USUARIO EN LOS ARCHIVOS DE CONFIGURACION
# CHANGING NAME USER ACCOUNT CONFIG FILES
function is_username(){
	is_user=`echo $USER`
	if [ "$is_user" ]; then
	find $gp/conf -type f -print0 | xargs -0 -I "{}" sed -i "s:tu_usuario:$is_user:g"  "{}"
   fi
}
is_username

# CAMBIANDO PARAMETROS DEL SERVIDOR
# CHANGING PARAMETERS SERVER
is_ask() {
    inquiry="$1"
    iresponse="$2"
    funcion="$3"

    while true; do
      read -p "$inquiry: " answer
      case $answer in
            [Yy]* )
             	# execute command yes
		    while true; do
            	answer=`$funcion`
            	if [ "$answer" ]; then
            	    echo $answer
            	    	break;
            	 else
            	    echo "$iresponse"
            	 fi
             done;
			break;;
          	[Nn]* )
		# execute command no
			break;;
        * ) echo; echo "${lm2[${es}]}: YES (y) or NO (n)";;
    esac
done
}

# IP-GATEWAY
function is_ip(){
	read -p "${lm3[${es}]} IP (e.g. 192.168.0.10): " IP
	IPNEW=`echo $IP | egrep '^(([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$'`
	if [ "$IPNEW" ]; then
	find $gp/conf -type f -print0 | xargs -0 -I "{}" sed -i "s:192.168.0.10:$IPNEW:g"  "{}"
	echo "${lm4[${es}]} la IP $IP"
   fi
}

# MASK
function is_mask1(){
	read -p "${lm3[${es}]} Netmask (e.g. 255.255.255.0): " MASK1
	MASKNEW1=`echo $MASK1 | egrep '^(([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$'`
	if [ "$MASKNEW1" ]; then
	find $gp/conf -type f -print0 | xargs -0 -I "{}" sed -i "s:255.255.255.0:$MASKNEW1:g"  "{}"
	echo "${lm4[${es}]} Netmask $MASK1"
   fi
}

function is_mask2(){
	read -p "${lm3[${es}]} Subnet-Mask (e.g. 24): " MASK2
	MASKNEW2=`echo $MASK2 | egrep '[0-9]'`
	if [ "$MASKNEW2" ]; then
	find $gp/conf -type f -print0 | xargs -0 -I "{}" sed -i "s:/24:/$MASKNEW2:g"  "{}"
	echo "${lm4[${es}]} Subnet-Mask $MASK2"
   fi
}

# DNS
function is_dns1(){
	read -p "${lm3[${es}]} DNS1 (e.g. 8.8.8.8): " DNS1
	DNSNEW1=`echo $DNS1 | egrep '^(([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$'`
	if [ "$DNSNEW1" ]; then
	find $gp/conf -type f -print0 | xargs -0 -I "{}" sed -i "s:8.8.8.8:$DNSNEW1:g"  "{}"
	echo "${lm4[${es}]} DNS1 $DNS1"
   fi
}

function is_dns2(){
	read -p "${lm3[${es}]} DNS2 (e.g. 8.8.4.4): " DNS2
	DNSNEW2=`echo $DNS2 | egrep '^(([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$'`
	if [ "$DNSNEW2" ]; then
	find $gp/conf -type f -print0 | xargs -0 -I "{}" sed -i "s:8.8.4.4:$DNSNEW2:g"  "{}"
	echo "${lm4[${es}]} DNS2 $DNS2"
   fi
}

# LOCALNET
function is_localnet(){
	read -p "${lm3[${es}]} Localnet-Network (e.g. 192.168.0.0): " LOCALNET
	LOCALNETNEW=`echo $LOCALNET | egrep '^(([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$'`
	if [ "$LOCALNETNEW" ]; then
	find $gp/conf -type f -print0 | xargs -0 -I "{}" sed -i "s:192.168.0.0:$LOCALNETNEW:g"  "{}"
	echo "${lm4[${es}]} Localnet-Network $LOCALNET"
   fi
}

# BROADCAST
function is_broadcast(){
	read -p "${lm3[${es}]} Broadcast (e.g. 192.168.0.255): " BROADCAST
	BROADCASTNEW=`echo $BROADCAST | egrep '^(([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$'`
	if [ "$BROADCASTNEW" ]; then
	find $gp/conf -type f -print0 | xargs -0 -I "{}" sed -i "s:192.168.0.255:$BROADCASTNEW:g"  "{}"
	echo "${lm4[${es}]} Broadcast $BROADCAST"
   fi
}

# INTERFACE LOCALNET
function is_eth(){
	read -p "${lm3[${es}]} DHCP Localnet Interface (e.g. 1): " ETH
	ETHNEW=`echo $ETH | egrep '[0-9]'` # '^([0-9])$'`
	if [ "$ETHNEW" ]; then
	find $gp/conf -type f -print0 | xargs -0 -I "{}" sed -i "s:eth1:eth$ETHNEW:g"  "{}"
	echo "${lm4[${es}]} DHCP Localnet Interface $ETH"
   fi
}

# DHCP RANGE
function is_rangeini(){
	read -p "${lm3[${es}]} DHCP-RANGE-INI (e.g. 192.168.0.100): " RANGEINI
	RANGEININEW=`echo $RANGEINI | egrep '^(([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$'`
	if [ "$RANGEININEW" ]; then
	find $gp/conf -type f -print0 | xargs -0 -I "{}" sed -i "s:192.168.0.100:$RANGEININEW:g"  "{}"
	echo "${lm4[${es}]} DHCP-RANGE-INI $RANGEINI"
   fi
}

function is_rangeend(){
	read -p "${lm3[${es}]} DHCP-RANGE-END (e.g. 192.168.0.250): " RANGEEND
	RANGEENDNEW=`echo $RANGEEND | egrep '^(([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$'`
	if [ "$RANGEENDNEW" ]; then
	find $gp/conf -type f -print0 | xargs -0 -I "{}" sed -i "s:192.168.0.250:$RANGEENDNEW:g"  "{}"
	echo "${lm4[${es}]} DHCP-RANGE-END $RANGEEND"
   fi
}

clear
echo
while true; do
	read -p "Parametros del servidor - Server settings:
IP 192.168.0.10, Mask 255.255.255.0 /24, DNS 8.8.8.8,8.8.4.4, eth1
Localnet 192.168.0.0, Broadcast 192.168.0.255, DHCP-Range 100-250
Desea modificarlos? - Do you want to change it? (y/n)" answer
		case $answer in
          [Yy]* )
		# execute command yes
	is_ask "${lm5[${es}]} IP 192.168.0.10? (y/n)" "${lm6[${es}]} IP incorrect" is_ip
	is_ask "${lm5[${es}]} Mask 255.255.255.0? (y/n)" "${lm6[${es}]} Mask incorrect" is_mask1
	is_ask "${lm5[${es}]} Sub-Mask /24? (y/n)" "${lm6[${es}]} Sub-Mask incorrect" is_mask2
	is_ask "${lm5[${es}]} DNS1 8.8.8.8? (y/n)" "${lm6[${es}]} DNS1 incorrect" is_dns1
	is_ask "${lm5[${es}]} DNS2 8.8.4.4? (y/n)" "${lm6[${es}]} DNS2 incorrect" is_dns2
	is_ask "${lm5[${es}]} Localnet 192.168.0.0? (y/n)" "${lm6[${es}]} Localnet incorrect" is_localnet
	is_ask "${lm5[${es}]} Broadcast 192.168.0.255? (y/n)" "${lm6[${es}]} Broadcast incorrect" is_broadcast
	is_ask "${lm5[${es}]} DHCP Localnet Interface? (y/n)" "${lm6[${es}]} Interface incorrect" is_eth
	is_ask "${lm5[${es}]} DHCP-RANGE-INI 192.168.0.100? (y/n)" "${lm6[${es}]} IP incorrect" is_rangeini
	is_ask "${lm5[${es}]} DHCP-RANGE-END 192.168.0.250? (y/n)" "${lm6[${es}]} IP incorrect" is_rangeend
	echo OK
			break;;
          	[Nn]* )
		# execute command no
			break;;
        * ) echo; echo "${lm2[${es}]}: YES (y) or NO (n)";;
    esac
done

# LOCALEPURGE (LANGUAGES)
clear
echo
while true; do
	read -p "${lm7[${es}]} LocalePurge (eng-spa)
(idiomas-languajes /etc/locale.nopurge)? (y/n)" answer
    	case $answer in
          [Yy]* )
		# execute command yes
	sudo cp -f $gp/conf/locale.nopurge /etc
	sudo apt -f install && sudo apt-get -y install localepurge && sudo apt -f install
	sudo localepurge && sudo locale-gen
	echo OK
			break;;
          	[Nn]* )
		# execute command no
			break;;
        * ) echo; echo "${lm2[${es}]}: YES (y) or NO (n)";;
    esac
done

clear
echo
echo "Eliminando servicios no esenciales - Deleting non-essential services..."
	gsettings set com.canonical.Unity.Lenses disabled-scopes "['more_suggestions-amazon.scope', 'more_suggestions-u1ms.scope', 'more_suggestions-populartracks.scope', 'music-musicstore.scope', 'more_suggestions-ebay.scope', 'more_suggestions-ubuntushop.scope', 'more_suggestions-skimlinks.scope']" && sleep 1 && gsettings set com.canonical.desktop.interface scrollbar-mode normal >/dev/null 2>&1
	sudo update-desktop-database
	echo OK
# CLEAN AND UPDATE
updateandclean(){
clear
echo
echo "Su sistema se esta actualizando - Your system is being updated..."
	sudo apt update && sleep 1 && sudo apt -y upgrade && sudo apt -y dist-upgrade && sleep 1 && sudo apt install --fix-missing -y && sleep 1 && sudo apt -f install && sudo fc-cache && sleep 1 && sudo sync && sleep 1 && sudo sysctl -w vm.drop_caches=3 vm.swappiness=10 && sleep 1 && sudo apt -y autoremove && sleep 1 && sudo apt -y autoclean && sleep 1 && sudo apt -y clean && sleep 1 && sudo dpkg --configure -a && sleep 1 && sudo apt -f install
}
updateandclean

# ESSENTIAL PACK
clear
echo
echo "Essential Pack setup..."
echo
	# Google Chrome
	wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | sudo apt-key add - && sleep 1 && sudo sh -c 'echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" > /etc/apt/sources.list.d/google-chrome.list' && sleep 1 && sudo gpg --keyserver keys.gnupg.net --recv-key A040830F7FAC5991 && sleep 1 && sudo gpg --export --armor $PUBKRY | sudo apt-key add -
	# Firefox
	sudo sh -c 'echo "deb http://ppa.launchpad.net/ubuntu-mozilla-security/ppa/ubuntu $(lsb_release -sc) main" >> /etc/apt/sources.list' && sleep 1 && sudo gpg --keyserver keys.gnupg.net --recv-key A6DCF7707EBC211F && sleep 1 && sudo gpg --export --armor $PUBKRY | sudo apt-key add -
	# Webmin
	sudo sh -c 'echo "deb http://download.webmin.com/download/repository sarge contrib" >> /etc/apt/sources.list' && wget -q http://www.webmin.com/jcameron-key.asc -O- | sudo apt-key add -
	# Systemback
	sudo add-apt-repository ppa:nemh/systemback --yes
    # Remove sendmail
	sudo service sendmail stop >/dev/null 2>&1 && sudo update-rc.d -f sendmail remove
	# Pack Install
	sudo apt update && sudo apt -f install && sudo apt -y install build-essential checkinstall cdbs devscripts dh-make fakeroot libxml-parser-perl check avahi-daemon automake make dpatch patchutils autotools-dev debhelper quilt xutils lintian cmake libtool autoconf git git-core subversion bzr gcc patch module-assistant libupnp-dev dkms linux-headers-$(uname -r) rcconf dialog aptitude bleachbit gksu libgksu2-0 vmm libglib2.0-0 ntfs-config dconf-editor dconf-tools jfsutils sysinfo hardinfo deborphan gtkorphan xsltproc lshw-gtk gedit curl openssl uudeview bluefish geany gparted xfsprogs reiserfsprogs reiser4progs kpartx dmraid util-linux preload prelink synaptic perl libwww-perl libmailtools-perl libmime-lite-perl librrds-perl libdbi-perl libxml-simple-perl libhttp-server-simple-perl libconfig-general-perl libio-socket-ssl-perl libdate-manip-perl libclass-dbi-mysql-perl libnet-ssleay-perl libauthen-pam-perl libpam-runtime libio-pty-perl apt-show-versions python python-pcapy python-cairo python-gi python-gobject python-gobject-2 python-gtk2 python-notify python-dev python-glade2 unattended-upgrades gnome-disk-utility gdebi gdebi-core unace zip unzip p7zip-full sharutils mpack arj cabextract rar unrar file-roller ipset vim ttf-dejavu hfsplus hfsprogs hfsutils hfsutils-tcltk exfat-fuse exfat-utils zenity w3m lsscsi winbind fping p7zip-rar linux-tools-common searchmonkey ppa-purge google-chrome-stable firefox webmin snapd systemback systemback-locales unetbootin rrdtool procps geoip-database netmask sipcalc ipcalc dmidecode libsasl2-modules postfix postfix-mysql postfix-doc mailutils netmask sysv-rc-conf && sudo apt -f install && sudo dpkg --configure -a && sudo apt -f install && sudo m-a prepare
	sudo cp -f /etc/postfix/master.cf{,.bak} >/dev/null 2>&1
	sudo cp -f $gp/conf/mail/master.cf /etc/postfix/master.cf
	sudo cp -f /etc/postfix/main.cf{,.bak} >/dev/null 2>&1
	sudo cp -f $gp/conf/mail/main.cf /etc/postfix/main.cf
	sudo chmod 777 /var/lib/update-notifier/package-data-downloads/partial
	sudo apt-get -y install ttf-mscorefonts-installer
    # freefilesync
    sudo add-apt-repository ppa:eugenesan/ppa --yes
    sudo apt update && sudo apt -y install freefilesync && sudo apt -f install
    # ubuntu-tweak
    sudo rm ubuntu-tweak*.deb >/dev/null 2>&1 && sudo apt -y purge ubuntu-tweak >/dev/null 2>&1
	wget -c --retry-connrefused -t 0 http://archive.getdeb.net/ubuntu/pool/apps/u/ubuntu-tweak/ubuntu-tweak_0.8.7-1~getdeb2~xenial_all.deb
	sudo dpkg -i --force-depends ubuntu-tweak_0.8.7-1~getdeb2~xenial_all.deb && sudo apt-get -f install
	echo OK
    # Opera
	latest=$(wget 'http://download4.operacdn.com/ftp/pub/opera/desktop/' -O - | grep -oP '[\d]+\.([\d]+\.?){1,4}' | sort -u | tail -1)
	wget -c --retry-connrefused -t 0 "http://download4.operacdn.com/ftp/pub/opera/desktop/$latest/linux/opera-stable_${latest}_amd64.deb"
	sudo apt -y install apt-transport-https libcurl3
    sudo dpkg -i opera*.deb && sudo apt-get install -f
	echo OK

updateandclean

# SERVERS
clear
echo
function is_servers(){
	echo "Apache2, DHCP, Squid, PHP7 setup..."
	sudo apt -f install && sudo apt -y install apache2 apache2-doc apache2-utils apache2-dev apache2-suexec-pristine libaprutil1 libaprutil1-dev isc-dhcp-server && sudo apt -f install
	sudo cp -f /etc/apache2/apache2.conf{,.bak} >/dev/null 2>&1
	sudo cp -f $gp/conf/apache/apache2.conf /etc/apache2/apache2.conf
	sudo apache2ctl configtest
	echo OK
	echo
	sudo add-apt-repository ppa:ondrej/php --yes
	sudo apt-get install -y language-pack-en-base python-software-properties
	sudo apt update && sudo apt -f install && sudo apt -y install php7.0 php7.0-common php7.0-mysql libmcrypt-dev mcrypt php7.0-mcrypt php7.0-gd php-xml php-xml-parser php7.0-curl php-soap libapr1 libaprutil1 libaprutil1-dbd-sqlite3 libaprutil1-ldap php7.0-mysql php7.0-dev php-pear libapache2-mod-php php-gettext php-xml php-soap php-mcrypt && sudo apt -f install
	echo OK
	echo
	sudo apt -y install squid squidclient squid-cgi squid-langpack && sudo apt -f install
	sudo service squid stop && sleep 3
	sudo rm -rf /var/spool/squid/* && sleep 3
	sudo squid -z && sleep 3
	sudo crontab -l | { cat; echo "@weekly squid -k rotate"; } | sudo crontab -
	echo OK
}
is_servers

updateandclean

# PROXY
clear
echo
echo "Activacion del Proxy - Activation Proxy..."
echo
function is_port(){
	read -p "${lm3[${es}]} Proxy Port (e.g. 3128): " PORT
	PORTNEW=`echo $PORT | egrep '[1-9]'`
	if [ "$PORTNEW" ]; then
	find $gp/conf -type f -print0 | xargs -0 -I "{}" sed -i "s:3128:$PORTNEW:g"  "{}"
	echo "${lm4[${es}]} Proxy Port $PORT"
   fi
}

function is_intercept(){
	sed -i '/PROXYINTERCEPT/r $gp/conf/proxy/iptintercept.txt' $gp/conf/scripts/iptables.sh
	sed -i '/PROXYINTERCEPT/r $gp/conf/proxy/squidintercept.txt' $gp/conf/squid/squid.conf
	sed -i '/CACHEPEER/r $gp/conf/proxy/cpintercept.txt' $gp/conf/squid/squid.conf
	sed -i "s:3128:8080:g" $gp/conf/monitor/config.inc.php
	sed -i "s:3128:8080:g" $gp/conf/squid/cachemgr.conf
	echo OK
}

function is_proxy(){
	echo "Activando la autoconfiguracion del proxy WPAD-PAC..."
	sudo mkdir -p /etc/proxy >/dev/null 2>&1
	sudo cp -f $gp/conf/proxy/proxy.pac /etc/proxy
	sudo cp -f $gp/conf/proxy/wpad.da /etc/proxy
	sudo cp -f $gp/conf/proxy/wpad.dat /etc/proxy
	sudo cp -f $gp/conf/proxy/proxy.conf /etc/apache2/sites-enabled/proxy.conf
	sed -i '/PROXY/r $gp/conf/proxy/proxyport.txt' $gp/conf/apache/ports.conf
	sed -i '/WPAD-PAC/r $gp/conf/proxy/iptwpad.txt' $gp/conf/scripts/iptables.sh
	sed -i '/CACHEPEER/r $gp/conf/proxy/cpproxy.txt' $gp/conf/squid/squid.conf
	echo OK
	echo "WPAD-PAC: http://192.168.0.10:8000/proxy.pac"
}

while true; do
	read -p "Proxy Squid - Firewall Iptables
Recommend: Proxy No-Transparent (n)

 Y ${lm9[${es}]} Transparent Proxy (NAT 8080)-443 port filtering
 N ${lm9[${es}]} No-Transparent Proxy (3128)-WPAD-PAC (y/n)" answer
		case $answer in
          [Yy]* )
		# execute command yes
	echo	
	is_intercept
	echo OK
			break;;
          [Nn]* )
		# execute command no
	echo
	is_ask "${lm5[${es}]} Proxy Port 3128? (y/n)" "${lm6[${es}]} Proxy Port incorrect" is_port
	echo
	is_proxy
	echo OK
			break;;
        * ) echo; echo "${lm2[${es}]}: YES (y) or NO (n)";;
    esac
done

# REPORTS, LOGS AND MONITORING
clear
echo
function is_top(){
	echo "Top Family (Htop, Apachetop, iotop, Ntop-ng), nethogs, nload setup..."
	sudo apt -f install && sudo apt -y install nload nethogs htop apachetop iotop libpcap-dev libglib2.0-dev libgeoip-dev redis-server geoip-database ruby-redis ntopng ntopng-data && sudo apt -f install
	#sudo chown root:root /var/lib/redis >/dev/null 2>&1
	sudo cp -f $gp/conf/monitor/geoip.sh /etc/init.d
	sudo chown root:root /etc/init.d/geoip.sh
	sudo chmod +x /etc/init.d/geoip.sh
	sudo /etc/init.d/geoip.sh
	sudo service redis-server restart && sudo service ntopng restart
	sudo crontab -l | { cat; echo "@weekly /etc/init.d/geoip.sh"; } | sudo crontab -
	sudo crontab -l | { cat; echo "@monthly /usr/bin/find /var/tmp/ntopng/*/top_talkers/* -mtime +60 -delete >/dev/null 2>&1"; } | sudo crontab -
	echo '# Ntopng and redis-server
	date=`date +%d/%m/%Y" "%H:%M:%S`
	if [[ `ps -A | grep ntopng` != "" ]];then
	echo -e "\nONLINE"
	else
	echo -e "\n"
	killall -9 ntopng && service ntopng start
	echo "<--| Ntopng start $date |-->" >> /var/log/alert.log
	fi
	date=`date +%d/%m/%Y" "%H:%M:%S`
	#
	if [[ `ps -A | grep redis-server` != "" ]];then
	echo -e "\nONLINE"
	else
	echo -e "\n"
	killall -9 redis-server && service redis-server start
	echo "<--| redis-server start $date |-->" >> /var/log/alert.log
	fi'>> $gp/conf/scripts/servicesreload.sh
	echo OK
	echo "Ntop-ng: http://localhost:3000 user: admin pass: admin"
	echo
}

function is_sqstat(){
	echo "SQSTAT setup..."
	sudo tar -xf $gp/conf/monitor/sqstat-1.20.tar.gz
	sudo mkdir -p /var/www/html/sqstat
	sudo cp -f -R sqstat-1.20/* /var/www/html/sqstat/
	sudo cp -f $gp/conf/monitor/config.inc.php /var/www/html/sqstat/config.inc.php
	sudo rm -R sqstat-1.20
	echo OK
	echo "Sqstat: http://localhost/sqstat/sqstat.php"
	echo
}

function is_sarg(){
	echo "SARG setup..."
	sudo apt -f install && sudo apt -y install sarg && sudo apt -f install
	sudo mkdir -p /var/www/html/squid-reports
	sudo cp -f /etc/sarg/sarg.conf{,.bak} >/dev/null 2>&1
	sudo cp -f $gp/conf/monitor/sarg.conf /etc/sarg/sarg.conf
	sudo cp -f /etc/sarg/usertab{,.bak} >/dev/null 2>&1
	sudo cp -f $gp/conf/monitor/usertab /etc/sarg/usertab
	sudo cp -f $gp/conf/monitor/sargaudit.conf /etc/apache2/sites-enabled/sargaudit.conf
	sed -i '/SARG/r $gp/conf/monitor/iptsarg.txt' $gp/conf/scripts/iptables.sh
	sed -i '/SARG/r $gp/conf/monitor/sargport.txt' $gp/conf/apache/ports.conf
	sudo crontab -l | { cat; echo "@daily sarg -l /var/log/squid/access.log -o /var/www/html/squid-reports >/dev/null 2>&1"; } | sudo crontab -
	sudo crontab -l | { cat; echo '@monthly find /var/www/html/squid-reports -name "2*" -mtime +30 -type d -exec rm -rf "{}" \; >/dev/null'; } | sudo crontab -
	echo OK
	echo "Sarg: http://192.168.0.10:11500"
	echo "Usernames: /etc/sarg/usertab (e.g. 192.168.0.10 GATEPROXY)"
	echo
}

function is_iptraf(){
	echo "Iptraf setup..."
	sudo apt -f install && sudo apt -y install iptraf && sudo apt -f install
	sudo mkdir -p /var/www/html/iptrafaudit
	sudo touch /var/www/html/iptrafaudit/iptrafaudit.log
	sudo touch /var/log/iptraf/ip_traffic-1.log >/dev/null 2>&1
	sudo cp -f $gp/conf/monitor/iptrafaudit.conf /etc/apache2/sites-enabled/iptrafaudit.conf
	sed -i '/IPTRAF/r $gp/conf/monitor/iptiptraf.txt' $gp/conf/scripts/iptables.sh
	sed -i '/IPTRAF/r $gp/conf/monitor/iptrafport.txt' $gp/conf/apache/ports.conf
	sudo crontab -l | { cat; echo "@daily tail -50 /var/log/iptraf/ip_traffic-1.log > /var/www/html/iptrafaudit/iptrafaudit.log"; } | sudo crontab -
	echo '# Iptraf Service
	date=`date +%d/%m/%Y" "%H:%M:%S`
	if [[ `ps -A | grep iptraf` != "" ]];then
	echo -e "\nONLINE"
	else
	echo -e "\n"
	killall -9 iptraf
	iptraf -i all -L /var/log/iptraf/ip_traffic-1.log -B
	service apache2 restart
	echo "<--| Iptraf start $date |-->" >> /var/log/alert.log
	fi'>> $gp/conf/scripts/servicesreload.sh
	echo OK
	echo "Iptraf: http://192.168.0.10:11300/iptrafaudit.log"
	echo
}

function is_monitor(){
	echo "Webalizer, Monitorix setup..."
	sudo sh -c 'echo "deb http://apt.izzysoft.de/ubuntu generic universe" >> /etc/apt/sources.list' && wget -q http://apt.izzysoft.de/izzysoft.asc -O- | sudo apt-key add -
	sudo apt update && sudo apt -f install && sudo apt -y install webalizer monitorix && sudo apt -f install
	sudo mkdir -p /var/www/html/webalizer
	sudo cp -f /etc/webmin/webalizer/config{,.bak} >/dev/null 2>&1
	sudo cp -f $gp/conf/monitor/config /etc/webmin/webalizer/config
	sudo cp -f /etc/webalizer/webalizer.conf{,.bak} >/dev/null 2>&1
	sudo cp -f $gp/conf/monitor/webalizer.conf /etc/webalizer/webalizer.conf
	sudo cp -f /etc/monitorix/monitorix.conf{,.bak} >/dev/null 2>&1
	sudo cp -f $gp/conf/monitor/monitorix.conf /etc/monitorix/monitorix.conf
	echo "${lm3[${es}]} Monitorix password..."
	sudo htpasswd -d -c /var/lib/monitorix/htpasswd $USER
	sed -i '/MONITORIX/r $gp/conf/monitor/iptmonitorix.txt' $gp/conf/scripts/iptables.sh
	echo '# Monitorix Service
	date=`date +%d/%m/%Y" "%H:%M:%S`
	if [[ `ps -A | grep monitorix-httpd` != "" ]];then
	echo -e "\nONLINE"
	else
	echo -e "\n"
	killall -9 monitorix && service monitorix start && service apache2 restart
	echo "<--| Monitorix start $date |-->" >> /var/log/alert.log
	fi'>> $gp/conf/scripts/servicesreload.sh
	echo OK
	echo "Monitorix: http://localhost:8081/monitorix/"
	echo
}

function is_bandwidthd(){
	echo "Bandwidthd Monitor setup..."
	sudo rm -rf /var/www/html/bandwidthd /etc/bandwidthd /var/lib/bandwidthd >/dev/null 2>&1
	sudo mkdir -p /var/www/html/bandwidthd
	sudo apt -y install bandwidthd 
	sudo cp -f /etc/bandwidthd/bandwidthd.conf{,.bak} >/dev/null 2>&1
	sudo cp -f $gp/conf/monitor/bandwidthd.conf /etc/bandwidthd/bandwidthd.conf
	sudo cp -f $gp/conf/monitor/bandwidthdaudit.conf /etc/apache2/sites-enabled/bandwidthdaudit.conf
	sudo cp -f $gp/conf/monitor/logo.gif /var/www/html/bandwidthd/logo.gif
	sudo rm -rf /var/lib/bandwidthd/htdocs >/dev/null 2>&1
	sed -i '/bandwidthd/r $gp/conf/monitor/iptbandwidthd.txt' $gp/conf/scripts/iptables.sh
	sed -i '/bandwidthd/r $gp/conf/monitor/bandwidthdport.txt' $gp/conf/apache/ports.conf
	echo '# Bandwidthd Service
	date=`date +%d/%m/%Y" "%H:%M:%S`
	if [[ `ps -A | grep bandwidthd` != "" ]];then
	echo -e "\nONLINE"
	else
	echo -e "\n"
	killall -9 bandwidthd && /etc/init.d/bandwidthd start && service apache2 restart
	echo "<--| Bandwidthd start $date |-->" >> /var/log/alert.log
	fi'>> $gp/conf/scripts/servicesreload.sh
	echo OK
	echo "Bandwidthd: http://192.168.0.10:11400"
	echo
}

function is_speedtest(){
	echo "Speedtest setup..."
	sudo apt -y install python-pip && sudo apt -f install && sudo pip install --upgrade pip && sudo pip install speedtest-cli
	echo OK
	echo "Test console: speedtest"
	echo
}

function is_netdata(){
	echo "Netdata setup..."
	sudo apt -y install zlib1g-dev uuid-dev libmnl-dev autogen pkg-config jq nodejs && sudo apt -f install
	git clone https://github.com/firehol/netdata.git --depth=1
	cd netdata
	sudo ./netdata-installer.sh
	echo '# NetData Service
	date=`date +%d/%m/%Y" "%H:%M:%S`
	if [[ `ps -A | grep netdata` != "" ]];then
	echo -e "\nONLINE"
	else
	echo -e "\n"
	killall -9 netdata && /usr/sbin/netdata
	echo "<--| NetData start $date |-->" >> /var/log/alert.log
	fi'>> $gp/conf/scripts/servicesreload.sh
	echo OK
	echo "Netdata: http://localhost:19999/"
}

function is_logs(){
	echo "Logwatch, Logrotate, Ulogd2, logtail, Awstats, darkstat setup..."
	sudo apt -y install logwatch logrotate ulogd2 acct awstats logtail darkstat && sudo apt -f install
	sudo usermod -a -G ulog $USER
	sudo mv /etc/cron.daily/00logwatch /etc/cron.weekly/
	sudo cp -f /etc/cron.weekly/00logwatch{,.bak} >/dev/null 2>&1
	# sudo logwatch | less
	sudo touch /var/log/wtmp
	sudo cp -f $gp/conf/logs/pacct-report /etc/cron.weekly/pacct-report
	sudo chmod +x /etc/cron.weekly/pacct-report
	sudo cp -f $gp/conf/logs/00logwatch /etc/cron.weekly/00logwatch
	sudo chown root:root /var/log
	sudo cp -f /etc/cron.d/awstats{,.bak} >/dev/null 2>&1
	sudo cp -f $gp/conf/logs/awstats /etc/cron.d/awstats
	sudo cp -f $gp/conf/logs/init.cfg /etc/darkstat/init.cfg
	sudo sysv-rc-conf darkstat on
    echo '# Darkstat Service
	date=`date +%d/%m/%Y" "%H:%M:%S`
	if [[ `ps -A | grep darkstat` != "" ]];then
	echo -e "\nONLINE"
	else
	echo -e "\n"
    killall -9 darkstat && /etc/init.d/darkstat start && /etc/init.d/darkstat restart
	/usr/sbin/netdata
	echo "<--| Darkstat start $date |-->" >> /var/log/alert.log
	fi'>> $gp/conf/scripts/servicesreload.sh
	echo "darkstat: http://localhost:666//"
	echo OK
	echo
}

function is_goaccess(){
	echo "goaccess setup..."
	echo "deb http://deb.goaccess.io/ $(lsb_release -cs) main" | sudo tee -a /etc/apt/sources.list.d/goaccess.list
	wget -O - http://deb.goaccess.io/gnugpg.key | sudo apt-key add -
	sudo apt update && sudo apt -y install goaccess
	sudo mkdir -p /var/www/html/goaccess
	sudo touch /var/www/html/goaccess/goaccess.html
	sudo cp -f /etc/goaccess.conf{,.bak} >/dev/null 2>&1
	sudo cp -f $gp/conf/logs/goaccess.conf /etc/goaccess.conf
	sudo cp -f $gp/conf/logs/goaccessaudit.conf /etc/apache2/sites-enabled/goaccessaudit.conf
	sed -i '/goaccess/r $gp/conf/logs/iptgoaccess.txt' $gp/conf/scripts/iptables.sh
	sed -i '/goaccess/r $gp/conf/logs/goaccessport.txt' $gp/conf/apache/ports.conf
	sudo crontab -l | { cat; echo '@daily zcat `find /var/log/apache2/ -name "access.log.*.gz" -mtime -35` | goaccess > /var/www/html/goaccess/goaccess.html'; } | sudo crontab -
	echo OK
	echo "Goaccess logs: http://192.168.0.10:11700"
	echo
}

sudo crontab -l | { cat; echo "@daily tail -50 /var/log/iptraf/ip_traffic-1.log > /var/www/html/iptrafaudit/iptrafaudit.log"; } | sudo crontab -

while true; do
    read -p "${lm7[${es}]} Pack Reports, Logs, Monitoring? (recommended-recomendado)
Sqstat, NetData, Iptraf, nethogs, Webalizer, Monitorix, Bandwidthd,
Logwatch, Speedtest, darkstat, nload, Sarg, Htop, Apachetop, iotop, 
Ntop-ng, Logrotate, Ulogd2, logtail, awstats, goaccess (y/n)" answer
		case $answer in
          [Yy]* )
		# execute command yes
	is_top
	is_sqstat
	is_sarg
	is_iptraf
	is_monitor
	is_bandwidthd
	is_speedtest
	is_netdata
	is_logs
	is_goaccess
	echo OK
			break;;
          	[Nn]* )
		# execute command no
			break;;
        * ) echo; echo "${lm2[${es}]}: YES (y) or NO (n)";;
    esac
done

# OPCIONAL PACK
clear
echo

function is_mate(){
# Mate Desktop
clear
echo

is_mate=`which mate-panel`
    if [ "$is_mate" ]; then
        echo "Mate Desktop ${lm10[${es}]}"
    else
        while true; do
        read -p "${lm7[${es}]} Mate Desktop? (y/n)" answer
    	case $answer in
          [Yy]* )
		# execute command yes
	sudo add-apt-repository ppa:ubuntu-mate-dev/$(lsb_release -sc)-mate --yes
	sudo apt update && sudo apt -y dist-upgrade && sudo apt -f install
	# Vanilla MATE
	sudo apt -y install mate-desktop-environment-extras mate-dock-applet mate-applets
	echo OK
			break;;
          	[Nn]* )
		# execute command no
			break;;
        * ) echo; echo "${lm2[${es}]}: YES (y) or NO (n)";;
    esac
done
fi
}

function is_vbox(){
# VirtualBox
clear
echo
while true; do
	read -p "${lm7[${es}]} Virtualbox Pack? (y/n)" answer
		case $answer in
          [Yy]* )
		# execute command yes
	echo "Virtualbox Pack setup..."
 	echo "deb http://download.virtualbox.org/virtualbox/debian $(lsb_release -sc) contrib" | sudo tee /etc/apt/sources.list.d/virtualbox.list
	wget -q https://www.virtualbox.org/download/oracle_vbox_2016.asc -O- | sudo apt-key add -
	vboxmanage list runningvms >/dev/null 2>&1 | sed -r 's/.*\{(.*)\}/\1/' | xargs -L1 -I {} VBoxManage controlvm {} savestate >/dev/null 2>&1
	sudo apt -y autoremove --purge virtualbox* >/dev/null 2>&1
	sudo rm -rf /etc/vbox >/dev/null 2>&1
	sudo apt update && sudo apt -f install && sudo apt -y install virtualbox-5.0 bridge-utils && sudo dpkg --configure -a && sudo apt -f install
	cd /tmp
	export VBOX_VER=`VBoxManage --version|awk -Fr '{print $1}'`
	sudo VBoxManage extpack uninstall "Oracle VM VirtualBox Extension Pack" >/dev/null 2>&1
	wget http://download.virtualbox.org/virtualbox/$VBOX_VER/Oracle_VM_VirtualBox_Extension_Pack-$VBOX_VER.vbox-extpack
	sudo VBoxManage extpack install Oracle_VM_VirtualBox_Extension_Pack-$VBOX_VER.vbox-extpack && sudo apt -f install
	cd
	#sudo adduser $USER vboxusers
	sudo usermod -a -G vboxusers $USER
	echo "check groups $USER"
	sudo cp -f $gp/conf/virtual/vm /etc/init.d/vm
	sudo chown root:root /etc/init.d/vm
	sudo chmod +x /etc/init.d/vm
	sudo update-rc.d vm defaults 99 01
	echo "PHPVirtualbox setup..."
	sudo mkdir -p /var/www/html/phpvirtualbox
	cd /tmp/
	sudo wget -c --retry-connrefused -t 0 http://downloads.sourceforge.net/project/phpvirtualbox/phpvirtualbox-5.0-5.zip
	sudo unzip phpvirtualbox-5.0-5.zip
	sudo cp -R phpvirtualbox-5.0-5/* /var/www/html/phpvirtualbox/
	sudo rm -R phpvirtualbox-5.0-5*
	cd
	sudo cp $gp/conf/virtual/config.php /var/www/html/phpvirtualbox/config.php
	sudo cp $gp/conf/virtual/virtualbox /etc/default/virtualbox
	sudo cp $gp/conf/virtual/phpvboxaudit.conf /etc/apache2/sites-enabled/phpvboxaudit.conf
	sudo chown -R www-data:www-data /var/www/html/phpvirtualbox
	sed -i '/PHPVIRTUALBOX/r $gp/conf/virtual/iptphpvbox.txt' $gp/conf/scripts/iptables.sh
	sed -i '/PHPVIRTUALBOX/r $gp/conf/virtual/phpvboxport.txt' $gp/conf/apache/ports.conf
	sed -i '/VBOXWEBSERV/r $gp/conf/virtual/vboxweb.txt' $gp/conf/scripts/servicesreload.sh
	echo OK
	echo "VMs: http://192.168.0.10:11600"
	echo
		break;;
          	[Nn]* )
		# execute command no
			break;;
        * ) echo; echo "${lm2[${es}]}: YES (y) or NO (n)";;
    esac
done
}

function is_gdiskdump(){
# Gdiskdump
clear
echo
while true; do
	read -p "${lm7[${es}]} gdiskdump (Disk Clone)? (y/n)" answer
		case $answer in
          [Yy]* )
		# execute command yes
	sudo rm gdiskdump*.deb >/dev/null 2>&1 && sudo apt -y purge gdiskdump >/dev/null 2>&1
	wget -c --retry-connrefused -t 0 https://launchpad.net/gdiskdump/trunk/0.8/+download/gdiskdump_0.8-1_all.deb
	sudo dpkg -i gdiskdump_0.8-1_all.deb && sudo apt -f install
	echo OK
			break;;
          	[Nn]* )
		# execute command no
			break;;
        * ) echo; echo "${lm2[${es}]}: YES (y) or NO (n)";;
    esac
done
}

function is_remote(){
# Remote Desktop
clear
echo
while true; do
	read -p "${lm7[${es}]} Remote Desktop (Teamviewer, Remmina)? (y/n)" answer
		case $answer in
          [Yy]* )
		# execute command yes
	echo "Remmina setup..."
	sudo apt -y install remmina && sudo apt -f install
	echo OK
	echo "Teamviewer setup..."
	sudo apt-get -y purge teamviewer* >/dev/null 2>&1
	sudo dpkg -r teamviewer:i386 >/dev/null 2>&1
	sudo rm -rf ~\.local\share\TeamViewer* >/dev/null 2>&1
	sudo dpkg --add-architecture i386 && sudo apt update && sudo apt -f install
	sudo apt -y install libjpeg62
	sudo wget -c --retry-connrefused -t 0 http://download.teamviewer.com/download/teamviewer_i386.deb
	sudo dpkg -i --force-depends teamviewer_i386.deb && sudo dpkg --configure -a && sudo apt -f install
	sudo rm teamviewer_i386.deb
	echo '# Teamviewer service
	date=`date +%d/%m/%Y" "%H:%M:%S`
	if [[ `ps -A | grep teamviewerd` != "" ]];then
	echo -e "\nONLINE"
	else
	echo -e "\n"
	killall -9 teamviewerd && teamviewer --daemon start
	echo "<--| Teamviewer start $date |-->" >> /var/log/alert.log
	fi'>> $gp/conf/scripts/servicesreload.sh
	echo OK
		break;;
          	[Nn]* )
		# execute command no
			break;;
        * ) echo; echo "${lm2[${es}]}: YES (y) or NO (n)";;
    esac
done
}

function is_vnc(){
# VNC Server Remote Desktop
clear
echo
while true; do
	read -p "${lm7[${es}]} VNC server (Vino)? (y/n)" answer
		case $answer in
          [Yy]* )
		# execute command yes
	echo
	echo "VNC Vino-Server setup..."
	sudo apt -y install vino && sudo apt -f install
	vino-preferences
	sudo cp $gp/conf/vnc/vino-server.sh /etc/init.d/vino-server.sh
	sudo chown root:root /etc/init.d/vino-server.sh
	sudo chmod +x /etc/init.d/vino-server.sh
	echo OK
	echo "VNC: sudo /etc/init.d/vnc-server.sh start"
		break;;
          	[Nn]* )
		# execute command no
			break;;
        * ) echo; echo "${lm2[${es}]}: YES (y) or NO (n)";;
    esac
done
}

function is_samba(){
# SAMBA
clear
echo
while true; do
	read -p "${lm7[${es}]} Samba ${cm11[${es}]}
${cm12[${es}]}? (y/n)" answer
		case $answer in
          [Yy]* )
            	# execute command yes
	is_user=`echo $USER`
	if [ "$is_user" ]; then
	find $gp/conf/samba -type f -print0 | xargs -0 -I "{}" sed -i "s:tu_smbd:$is_user:g"  "{}"
    fi
	mkdir -p compartida
	sudo mkdir -p /var/www/html/smbdaudit
	sudo touch /var/www/html/smbdaudit/smbdaudit.log
	sudo cp -f $gp/conf/samba/smbdaudit.conf /etc/apache2/sites-enabled/smbdaudit.conf
	sudo apt -f install && sudo apt -y install samba samba-common smbclient system-config-samba && sudo apt -f install
	sudo cp -f /etc/logrotate.d/samba{,.bak} >/dev/null 2>&1
	sudo cp -f $gp/conf/samba/samba /etc/logrotate.d/samba
	sudo cp -f /etc/samba/smb.conf{,.bak} >/dev/null 2>&1
	sudo cp -f $gp/conf/samba/smb.conf /etc/samba/smb.conf
	sudo chmod +x $gp/conf/samba/sambacron.sh && sudo $gp/conf/samba/sambacron.sh
	sed -i '/SAMBA/r $gp/conf/samba/iptsamba.txt' $gp/conf/scripts/iptables.sh
	sed -i '/SAMBA/r $gp/conf/samba/sambaport.txt' $gp/conf/apache/ports.conf
	echo '# Samba Service Smbd
	date=`date +%d/%m/%Y" "%H:%M:%S`
	if [[ `ps -A | grep smbd` != "" ]];then
	echo -e "\nONLINE"
	else
	echo -e "\n"
	killall -9 smbd && killall -9 nmbd
	systemctl restart smbd && systemctl restart nmbd
	echo "<--| Samba (smbd) start $date |-->" >> /var/log/alert.log
	fi
	#
	# Samba Service Nmbd
	date=`date +%d/%m/%Y" "%H:%M:%S`
	if [[ `ps -A | grep nmbd` != "" ]];then
	echo -e "\nONLINE"
	else
	echo -e "\n"
	killall -9 smbd && killall -9 nmbd
	systemctl restart smbd && systemctl restart nmbd
	echo "<--| Samba (nmbd) start $date |-->" >> /var/log/alert.log
	fi
	'>> $gp/conf/scripts/servicesreload.sh
	echo OK
	echo "Samba Audit: http://192.168.0.10:11200/smbdaudit.log"	
		break;;
          	[Nn]* )
		# execute command no
			break;;
        * ) echo; echo "${lm2[${es}]}: YES (y) or NO (n)";;
    esac
done
}

while true; do
	read -p "${lm7[${es}]} Optional Pack?
Mate Desktop, Virtualbox Pack, gdiskdump, Samba,
Vino server, Remote Pack Teamviewer-Remmina (y/n)" answer
		case $answer in
          [Yy]* )
		# execute command yes
	is_mate
	is_vbox
	is_gdiskdump
	is_remote
	is_vnc
	is_samba
	echo OK
			break;;
          	[Nn]* )
		# execute command no
			break;;
        * ) echo; echo "${lm2[${es}]}: YES (y) or NO (n)";;
    esac
done

# SECURITY PACK

function is_security(){
clear
echo
while true; do
   read -p "${lm7[${es}]} Security Pack? (${lm1[${es}]})
Fail2ban, DDOSDeflate, Mod Security, OWASP, Evasive, Rootkitchk (y/n)" answer
		case $answer in
          [Yy]* )
		# execute command yes
	echo
	echo "Fail2Ban setup..."
	sudo apt -f install && sudo apt -y install fail2ban python-pyinotify python-gamin && sudo apt -f install
	sudo cp -f /etc/fail2ban/jail.conf{,.bak} >/dev/null 2>&1
	sudo cp -f /proc/sys/fs/inotify/max_user_instances{,.bak} >/dev/null 2>&1
	sudo cp -f $gp/conf/fail2ban/jail.conf /etc/fail2ban/jail.conf
	sudo cp -f $gp/conf/fail2ban/max_user_instances /proc/sys/fs/inotify/max_user_instances
	echo '# Fail2ban service
	date=`date +%d/%m/%Y" "%H:%M:%S`
	if [[ `ps -A | grep fail2ban-server` != "" ]];then
	echo -e "\nONLINE"
	else
	echo -e "\n"
    killall -9 fail2ban >/dev/null 2>&1
	rm -rf /var/run/fail2ban/fail2ban.sock >/dev/null 2>&1
	service fail2ban start && service rsyslog restart
	echo "<--| Fail2ban start $date |-->" >> /var/log/alert.log
	fi'>> $gp/conf/scripts/servicesreload.sh
	echo OK
	echo "Fail2ban report: /var/log/fail2ban.log"
	echo
	echo "DDOS Deflate setup..."
	sudo mkdir -p /usr/local/ddos
	sudo chown root:root /usr/local/ddos
	sudo cp -fR $gp/conf/ddos/* /usr/local/ddos
	sudo chmod 0700 /usr/local/ddos/uninstall.sh
	sudo chmod 0755 /usr/local/ddos/ddos.sh
	#sudo cp -fs /usr/local/ddos/ddos.sh /usr/local/sbin/ddos
	sudo crontab -l | { cat; echo "0-59/1 * * * * /usr/local/ddos/ddos.sh >/dev/null 2>&1"; } | sudo crontab -
	sleep 3
	echo OK
	echo "Para excluir ips edite: /usr/local/ddos/ignore"
	echo "Para desinstalar: /usr/local/ddos/uninstall.sh"
	echo "Para ver las ips baneadas: /usr/local/ddos/ddos.log"
	echo
	echo "Mod Security setup..."
	sudo apt -f install && sudo apt -y install libxml2-dev liblua5.1-0 lua5.1 libxml2 libcurl3 libcurl3-dev libxml2-utils libapache2-mod-evasive libapache2-modsecurity libapache2-mod-security2 modsecurity-crs && sudo dpkg --configure -a && sudo apt -f install
	sudo ln -sf /usr/lib/x86_64-linux-gnu/libxml2.so.2 /usr/lib/libxml2.so.2 >/dev/null 2>&1
	echo "Apache hardening..."
	sudo cp -f /etc/apache2/conf-enabled/security.conf{,.bak} >/dev/null 2>&1
	sudo cp -f $gp/conf/apache/security.conf /etc/apache2/conf-enabled/security.conf
	echo OK
	echo "Headers setup..."
	sudo ln -s /etc/apache2/mods-available/headers.load /etc/apache2/mods-enabled/headers.load
	echo "Enable mod_unique_id, rewrite and expires modules..."
	sudo a2enmod unique_id && sudo a2enmod rewrite && sudo a2enmod expires && sudo service apache2 restart
	echo "ModSecurity setup..."
	sudo cp -f /etc/modsecurity/modsecurity.conf{,.bak} >/dev/null 2>&1
	sudo cp -f $gp/conf/apache/modsecurity.conf /etc/modsecurity/modsecurity.conf
	# modsecurity anomalies 
	# sudo cp $gp/conf/apache/modsecurity_crs_21_protocol_anomalies.conf /etc/apache2/mod-security/modsecurity_crs_21_protocol_anomalies.conf
	echo
	echo "OWASP setup..."
	cd /tmp
	sudo wget -c --retry-connrefused -t 0 https://github.com/SpiderLabs/owasp-modsecurity-crs/archive/master.zip
	sudo unzip master.zip
	sudo cp -fr owasp-modsecurity-crs-master/* /etc/modsecurity/
	sudo mv /etc/modsecurity/modsecurity_crs_10_setup.conf.example /etc/modsecurity/modsecurity_crs_10_setup.conf
	sudo ls /etc/modsecurity/base_rules | xargs -I {} sudo ln -s /etc/modsecurity/base_rules/{} /etc/modsecurity/activated_rules/{}
	sudo ls /etc/modsecurity/optional_rules | xargs -I {} sudo ln -s /etc/modsecurity/optional_rules/{} /etc/modsecurity/activated_rules/{}
	cd
	echo
	echo "Configure Mod evasive..."
	sudo mkdir -p /var/log/mod_evasive >/dev/null 2>&1
	sudo touch /var/log/apache2/mod_evasive.log
	sudo chown www-data:www-data /var/log/apache2/mod_evasive.log
	sudo chown www-data:www-data /var/log/mod_evasive
	sudo cp -f /etc/apache2/mods-available/evasive.conf{,.bak} >/dev/null 2>&1
	sudo cp -f $gp/conf/apache/evasive.conf /etc/apache2/mods-available/evasive.conf
	sudo ln -s /etc/apache2/mods-available/evasive.conf /etc/apache2/mods-enabled/evasive.conf >/dev/null 2>&1
	sudo cp -f /etc/apache2/mods-available/mod-evasive.conf{,.bak} >/dev/null 2>&1
	sudo cp -f $gp/conf/apache/mod-evasive.conf /etc/apache2/mods-available/mod-evasive.conf
	echo "Reload services and check..."
	sudo a2enmod headers && sudo a2enmod evasive && sudo a2enmod security2 && sudo service apache2 restart
	sudo apachectl -M | grep security2
	sudo apachectl -M | grep evasive
	sudo apache2ctl configtest
	echo "Check: security2_module (shared),evasive20_module (shared),Syntax OK"
	echo OK
	echo "Check: tail /var/log/apache2/error.log"
	echo
	echo "Rootkit checkers setup..."
	sudo apt -f install && sudo apt -y install rkhunter chkrootkit && sudo apt -f install
	sudo rkhunter --update
	sudo cp -f /etc/chkrootkit.conf{,.bak} >/dev/null 2>&1
	sudo cp -f $gp/conf/apache/chkrootkit.conf /etc/chkrootkit.conf
	sudo cp -f /etc/default/rkhunter{,.bak} >/dev/null 2>&1
	sudo cp -f $gp/conf/apache/rkhunter /etc/default/rkhunter
	sudo crontab -l | { cat; echo "@weekly /usr/bin/rkhunter --cronjob --update --quiet"; } | sudo crontab -
	echo "Check: /var/log/rkhunter.log"
	echo OK
	echo
			break;;
          	[Nn]* )
		# execute command no
			break;;
        * ) echo; echo "${lm2[${es}]}: YES (y) or NO (n)";;
    esac
done
}

# DNS
clear
echo
function is_dnsmasq(){
while true; do
	read -p "${lm7[${es}]} DNS-LOCAL (dnsmasq)? (${lm1[${es}]})
deactivate resolvconf - restore resolv.conf (y/n)" answer
		case $answer in
          [Yy]* )
		# execute command yes
	echo "DNS-LOCAL dnsmasq setup..."
	sudo apt -f install && sudo apt -y install dnsmasq && sudo apt -f install
	sudo cp -f /etc/dnsmasq.conf{,.bak} >/dev/null 2>&1
	sudo cp -f $gp/conf/dnsmasq/dnsmasq.conf /etc/dnsmasq.conf
	sudo touch /var/log/dnsmasq.log
	sudo chown root:root /var/log/dnsmasq.log
	sudo cp -f $gp/conf/dnsmasq/dnsmasq /etc/logrotate.d/dnsmasq
	sudo cp -f /etc/default/dnsmasq{,.bak} >/dev/null 2>&1
	#sudo cp -f $gp/conf/dnsmasq/dnsmasqdefault /etc/default/dnsmasq
	sudo cp -f $gp/conf/dnsmasq/resolv.dnsmasq.conf /etc/resolv.dnsmasq.conf
	sed -i '/DNS-LOCAL/r $gp/conf/dnsmasq/iptdnslocal.txt' $gp/conf/scripts/iptables.sh
	sed -i '/outgoing_proxy/r $gp/conf/dnsmasq/squidoutgoing.txt' $gp/conf/squid/squid.conf
	sed -i '/dnsmasq_server/r $gp/conf/dnsmasq/squiddnslocal.txt' $gp/conf/squid/squid.conf
	sudo crontab -l | { cat; echo "@weekly cat >/dev/null /var/log/dnsmasq.log"; } | sudo crontab -
	echo '# Dnsmasq service
	date=`date +%d/%m/%Y" "%H:%M:%S`
	if [[ `netstat -plan | grep -w dnsmasq` != "" ]];then
	echo -e "\nONLINE"
	else
	echo -e "\n"
    killall -9 dnsmasq && /etc/init.d/dnsmasq start
	echo "<--| dnsmasq start $date |-->" >> /var/log/alert.log
	fi'>> $gp/conf/scripts/servicesreload.sh
	echo OK
	echo
	sudo dpkg-reconfigure resolvconf
	# sudo resolvconf -u
	sudo cp -f /etc/NetworkManager/NetworkManager.conf{,.bak}
	sudo cp -f $gp/conf/net/NetworkManager.conf /etc/NetworkManager/NetworkManager.conf
	sudo rm -rf /etc/resolv.conf >/dev/null 2>&1
	sudo cp -f $gp/conf/net/resolv.conf /etc/resolv.conf
	echo OK
			break;;
          	[Nn]* )
		# execute command no
	sed -i '/DNS-PUBLIC/r $gp/conf/dnsmasq/iptdnspublic.txt' $gp/conf/scripts/iptables.sh
	sed -i '/DNS-PUBLIC/r $gp/conf/dnsmasq/squiddnspublic.txt' $gp/conf/squid/squid.conf
	echo OK
	echo
			break;;
        * ) echo; echo "${lm2[${es}]}: YES (y) or NO (n)";;
    esac
done
}

function is_ids(){
# IDS/IPS (Experimental)
# https://www.digitalocean.com/community/tutorials/how-to-install-and-use-docker-on-ubuntu-16-04
# https://github.com/amabrouki/snort.git
clear
echo
while true; do
   read -p "NIPS/NIDS in Docker (Experimental):
${lm7[${es}]} Snort? (with Barnyard2, PulledPork, Snorby) (y/n)" answer
		case $answer in
          [Yy]* )
		# execute command yes
	echo "Docker setup..."
	sudo apt-key adv --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys 58118E89F3A912897C070ADBF76221572C52609D
	echo "deb https://apt.dockerproject.org/repo ubuntu-xenial main" | sudo tee /etc/apt/sources.list.d/docker.list
    	sudo apt update && sudo apt -f install && sudo apt -y install docker-engine
	sudo usermod -aG docker $(whoami)
	sudo systemctl enable docker && sudo systemctl start docker
	echo
	echo "Snort, Barnyard2, PulledPork, Snorby setup..."
	git clone https://github.com/amabrouki/snort.git
	cd snort && sudo docker build -t snort . && cd
	echo OK
	echo "Start: docker run  --privileged -it -p 3000:3000 -d snort"
	echo "HowTO: https://github.com/amabrouki/snort"
			break;;
          	[Nn]* )
		# execute command no
			break;;
        * ) echo; echo "${lm2[${es}]}: YES (y) or NO (n)";;
    esac
done
}

function is_clamav(){
# ANTIVIRUS
clear
echo
while true; do
   read -p "${lm7[${es}]} ClamAV-AntiVirus (Min 1GB RAM)? (y/n)" answer
		case $answer in
          [Yy]* )
		# execute command yes
	echo
	echo "ClamAV setup..."
	sudo apt -f install && sudo apt -y install clamav clamav-daemon clamav-freshclam && sudo apt -f install && sudo killall freshclam && sudo freshclam -v
    	sudo crontab -l | { cat; echo "@reboot /etc/init.d/clamav-daemon start"; } | sudo crontab -
	sudo crontab -l | { cat; echo "@reboot /etc/init.d/clamav-freshclam start"; } | sudo crontab -
    	echo '# Antivirus Clamav
	date=`date +%d/%m/%Y" "%H:%M:%S`
	if [[ `ps -A | grep clamav-daemon` != "" ]];then
	echo -e "\nONLINE"
	else
	echo -e "\n"
	service clamav-daemon start
	echo "<--| Clamav start $date |-->" >> /var/log/alert.log
	fi
	#
	if [[ `ps -A | grep freshclam` != "" ]];then
	echo -e "\nONLINE"
	else
	echo -e "\n"
	service clamav-freshclam start
	echo "<--| Clamav Update start $date |-->" >> /var/log/alert.log
	fi'>> $gp/conf/scripts/servicesreload.sh
	echo OK
	echo "Delete malware: sudo clamscan --infected --remove --recursive /home"
	echo OK
	echo
			break;;
          	[Nn]* )
		# execute command no
			break;;
        * ) echo; echo "${lm2[${es}]}: YES (y) or NO (n)";;
    esac
done
}

function is_pass(){
# PASSWORD
clear
echo
while true; do
    read -p "${lm7[${es}]} Encryption Pack? (${lm1[${es}]})
libpam-cracklib, 2-Factor Google Authentication, Veracrypt (y/n)" answer
		case $answer in
          [Yy]* )
		# execute command yes
	sudo apt -f install && sudo apt -y install libpam-cracklib
	sudo cp -f /etc/pam.d/common-password{,.bak} >/dev/null 2>&1
	sudo cp -f $gp/conf/security/common-password /etc/pam.d/common-password
	sudo apt -f install && sudo apt -y install libpam-google-authenticator
	sudo cp -f /etc/pam.d/common-auth{,.bak} >/dev/null 2>&1
	sudo cp -f $gp/conf/security/common-auth /etc/pam.d/common-auth
	sudo add-apt-repository ppa:unit193/encryption --yes
    sudo apt update && sudo apt -f install && sudo apt -y install veracrypt
	echo OK
			break;;
          	[Nn]* )
		# execute command no
			break;;
        * ) echo; echo "${lm2[${es}]}: YES (y) or NO (n)";;
    esac
done
}

function is_audit(){
# AUDIT
clear
echo
while true; do
    read -p "${lm7[${es}]} Network Audit Pack? (${lm1[${es}]})
Lynis, Nmap, Zenmap, ArpScan, python-nmap, Pipe Viewer, SSlscan, nbtscan,
cutter, wireshark, Hping, tcpdump, NetDiscover, My traceroute, Networking,
toolkit, Byobu, dsniff, wireless-tools (y/n)" answer
		case $answer in
          [Yy]* )
		# execute command yes
	sudo apt -f install && sudo apt -y install cutter wireshark nmap zenmap python-nmap lynis arp-scan hping3 pv net-tools mtr-tiny grc wireless-tools sslscan byobu traceroute nbtscan tcpdump dsniff && sudo apt -f install
	echo OK
			break;;
          	[Nn]* )
		# execute command no
			break;;
        * ) echo; echo "${lm2[${es}]}: YES (y) or NO (n)";;
    esac
done
}

# VPN
function is_vpn(){
clear
echo
while true; do
   read -p "VPN-Anonymizer Pack (Experimental)
${lm7[${es}]} FruhoVPN, OpenVPN, 4nonimizer? (y/n)" answer
		case $answer in
          [Yy]* )
		# execute command yes
	echo
		echo "FruhoVPN setup..."
	sudo rm fruho*.deb >/dev/null 2>&1 && sudo apt -y purge fruho >/dev/null 2>&1
	last=$(wget -O - https://github.com/fruho/fruhoapp/releases | grep -Po '/[^"]+download[^"]+' | grep deb | grep amd64 | sort | tail -1)
	wget https://github.com$last -O fruho.deb
	sudo dpkg -i fruho.deb && sudo apt-get install -f
	echo OK
	echo "OpenVPN setup..."
	sudo apt -f install && sudo apt -y install openvpn easy-rsa
    echo OK
    echo "4nonimizer setup"
	git clone https://github.com/Hackplayers/4nonimizer.git
	cd 4nonimizer && sudo chmod +x 4nonimizer && sudo ./4nonimizer install && cd
	echo OK
	echo "HowTO: https://github.com/Hackplayers/4nonimizer"
	echo
			break;;
          	[Nn]* )
		# execute command no
			break;;
        * ) echo; echo "${lm2[${es}]}: YES (y) or NO (n)";;
    esac
done
}

# BLACKUSB
clear
echo
function is_blackusb(){
while true; do
    read -p "${lm7[${es}]} Blackusb? (Experimental)
${cm13[${es}]} (y/n)" answer
		case $answer in
          [Yy]* )
		# execute command yes
	git clone https://github.com/maravento/blackusb.git
	sudo cp -f blackusb/blackusb /etc/init.d >/dev/null 2>&1
	sudo chown root:root /etc/init.d/blackusb
	sudo chmod +x /etc/init.d/blackusb
    	sudo /etc/init.d/blackusb on >/dev/null 2>&1
	sudo rm -rf blackusb >/dev/null 2>&1
	sudo crontab -l | { cat; echo "@reboot /etc/init.d/blackusb on"; } | sudo crontab -
	echo OK
	echo "HowTO https://github.com/maravento/blackusb"
			break;;
          	[Nn]* )
		# execute command no
			break;;
        * ) echo; echo "${lm2[${es}]}: YES (y) or NO (n)";;
    esac
done
}

clear
echo
while true; do
	read -p "${lm7[${es}]} Encryption, Security, VPN, DNS and Audit Pack (${lm1[${es}]}):

Fail2Ban, DDOS Deflate, Mod Security, OWASP, Mod evasive, Rootkit checkers,
Snort with Barnyard2, PulledPork, Snorby in Docker, ClamAV, libpam-cracklib,
2-Factor GoogleAuth, Veracrypt, Lynis, Nmap, Zenmap, ArpScan, SSLscan, cutter
python-nmap, Pipe Viewer, nbtscan, wireshark, Hping, tcpdump, dsniff, Byobu
My traceroute, Networking, toolkit, NetDiscover, wireless-tools, DNS-Local,
BlackUSB, VPN-Anonimizer Pack (${lm8[${es}]})? (y/n)" answer
		case $answer in
          [Yy]* )
		# execute command yes
	is_security
	is_dnsmasq
	is_ids
	is_clamav
	is_pass
	is_audit
	is_vpn
	is_blackusb
	echo OK
			break;;
          	[Nn]* )
		# execute command no
			break;;
        * ) echo; echo "${lm2[${es}]}: YES (y) or NO (n)";;
    esac
done

# CONFIG
clear
echo
echo "Blackweb, Blackip, Whiteip setup..."
git clone https://github.com/maravento/blackweb.git
sudo cp -f blackweb/blackweb.sh /etc/init.d >/dev/null 2>&1
tar -C blackweb -xvzf blackweb/blackweb.tar.gz >/dev/null 2>&1
sudo cp -f blackweb/{blackweb,blackdomains,whitedomains}.txt /etc/acl >/dev/null 2>&1
git clone https://github.com/maravento/blackip.git
sudo cp -f blackip/blackip.sh /etc/init.d >/dev/null 2>&1
tar -C blackip -xvzf blackip/blackip.tar.gz >/dev/null 2>&1
sudo cp -f blackip/blackip.txt /etc/acl >/dev/null 2>&1
git clone https://github.com/maravento/whiteip.git
sudo cp -f whiteip/whiteip.sh /etc/init.d >/dev/null 2>&1
sudo cp -f whiteip/whiteip.txt /etc/acl >/dev/null 2>&1
sudo chown root:root /etc/init.d/{blackweb,blackip,whiteip}.sh
sudo chmod +x /etc/init.d/{blackweb,blackip,whiteip}.sh
sudo rm -rf {blackweb,blackip,whiteip} >/dev/null 2>&1
sudo crontab -l | { cat; echo "@weekly /etc/init.d/blackweb.sh
@weekly /etc/init.d/blackip.sh
@weekly /etc/init.d/whiteip.sh"; } | sudo crontab -
echo OK
echo
echo "Applying configurations..."
sudo cp -f /etc/squid/squid.conf{,.bak} >/dev/null 2>&1
sudo cp -f /etc/squid/cachemgr.conf{,.bak} >/dev/null 2>&1
sudo cp -f $gp/conf/squid/{squid,cachemgr}.conf /etc/squid
sudo cp -f /etc/security/limits.conf{,.bak} >/dev/null 2>&1
sudo cp -f $gp/conf/security/limits.conf /etc/security/limits.conf
sudo cp -f /etc/apache2/ports.conf{,.bak} >/dev/null 2>&1
sudo cp -f $gp/conf/apache/ports.conf  /etc/apache2/ports.conf
sudo cp -f /etc/php/7.0/apache2/php.ini{,.bak} >/dev/null 2>&1
sudo cp -f $gp/conf/php7/php.ini /etc/php/7.0/apache2/php.ini
sudo cp -f /etc/network/interfaces{,.bak} >/dev/null 2>&1
sudo cp -f $gp/conf/net/interfaces /etc/network/interfaces
sudo cp -f /etc/hosts{,.bak} >/dev/null 2>&1
sudo cp -f $gp/conf/net/hosts /etc/hosts
sudo cp -f /etc/default/isc-dhcp-server{,.bak} >/dev/null 2>&1
sudo cp -f $gp/conf/dhcp/isc-dhcp-server /etc/default/isc-dhcp-server
sudo cp -f /etc/dhcp/dhclient.conf{,.bak} >/dev/null 2>&1
sudo cp -f $gp/conf/dhcp/dhclient.conf /etc/dhcp/dhclient.conf
sudo cp -f /etc/default/prelink{,.bak} >/dev/null 2>&1
sudo cp -f $gp/conf/prelink /etc/default/prelink
sudo cp -f $gp/conf/gateproxywp.jpg "Imágenes"/gateproxywp.jpg >/dev/null 2>&1
sudo cp -rf $gp/conf/scripts/{cleaner,iptables,leases,lock,logrotate,servicesreload,updatehour}.sh /etc/init.d
sudo chown root:root /etc/init.d/{cleaner,iptables,leases,lock,logrotate,servicesreload,updatehour}.sh
sudo chmod +x /etc/init.d/{cleaner,iptables,leases,lock,logrotate,servicesreload,updatehour}.sh
sudo cp -f $gp/conf/scripts/backup /etc/init.d
sudo chown root:root /etc/init.d/backup
sudo chmod +x /etc/init.d/backup
sudo cp -f /etc/sysctl.conf{,.bak} >/dev/null 2>&1
sudo cp -f $gp/conf/sysctl.conf /etc/sysctl.conf
sudo sysctl -p >/dev/null 2>&1
sudo sync
echo OK
clear
echo
echo "Create Apache Password /var/www/html..."
echo
sudo cp -f /etc/apache2/sites-enabled/000-default.conf{,.bak} >/dev/null 2>&1
sudo cp -f $gp/conf/apache/000-default.conf /etc/apache2/sites-enabled/000-default.conf
sudo htpasswd -c /etc/apache2/.htpasswd $USER
echo OK
echo
echo "Crontab tasks..."
sudo crontab -l | { cat; echo "
@reboot /etc/init.d/leases.sh
@reboot /etc/init.d/iptables.sh
@reboot /etc/init.d/updatehour.sh
@reboot /etc/init.d/lock.sh
*/03 * * * * /etc/init.d/servicesreload.sh
*/11 * * * * /etc/init.d/leases.sh
*/12 * * * * /etc/init.d/iptables.sh
@weekly /etc/init.d/logrotate.sh
@weekly /etc/init.d/cleaner.sh
@weekly journalctl --vacuum-size=500M
@weekly /etc/init.d/backup start"; } | sudo crontab -
sudo service cron restart
echo OK
echo
echo "Removing orphans..."
sudo deborphan | xargs sudo apt -y remove --purge
sudo deborphan --guess-data | xargs sudo apt -y remove --purge
sudo dpkg --configure -a && sudo apt -f install
echo OK
echo
echo "Clean and Update"
updateandclean
clear
echo
echo "Done. Presione ENTER para reiniciar - Press ENTER to reboot";
read RES
mkdir -p .local/share/Trash/files >/dev/null 2>&1
mv -f *.deb gateproxy* *.md5 .local/share/Trash/files >/dev/null 2>&1
history -c
sudo reboot
