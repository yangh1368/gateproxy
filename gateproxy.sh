#!/bin/bash
#####################################################################################
# (c) 2016. Gateproxy.com                                                           #
# Licence: Creative Commons Atribución-NoComercial-CompartirIgual 4.0 Internacional #
# HowTO: https://goo.gl/ZT4LTi                                                      #
# Install: git clone https://github.com/maravento/gateproxy.git                     #
# chmod +x gateproxy/gateproxy.sh && gateproxy/gateproxy.sh                         #
#####################################################################################
clear
gp=~/gateproxy
# CHECKING SO
function is_xenial(){
is_xenial=`lsb_release -sc | grep xenial`
	if [ "$is_xenial" ]; then
    echo
	echo "Sistema Operativo Correcto"
  else
	clear
	echo
	echo
	echo "Sistema Operativo Incorrecto. Instalacion abortada"
	echo "Asegurese de tener instalado Ubuntu 16.04.x LTS x64"
	echo
	exit
fi
}
is_xenial

# CHECKING INTERFACES
# DIRECCION MAC DE LA ETH PUBLICA
function is_mac_public(){
	read -p "Introduzca la MAC que usará para eth0 (Internet): " MAC
	if [ "$MAC" ]; then
	sed -i "s/00:00:00:00:00:00/$MAC/g" $gp/10-network.rules
   fi
}

# DIRECCION MAC DE LA ETH LOCAL
function is_mac_local(){
	read -p "Introduzca la MAC que usará para eth1 (Red Local): " MAC
	if [ "$MAC" ]; then
	sed -i "s/11:11:11:11:11:11/$MAC/g" $gp/10-network.rules
   fi
}

function is_interfaces(){
is_interfaces=`ifconfig | grep eth`
	if [ "$is_interfaces" ]; then
	echo
	echo "Formato de Interfaces de Red Correcto"
  else
	echo
	echo "Formato de Interfaces de Red Incorrecto"
	echo "Interfaces de red detectadas con sus direcciones MACs:"
	echo
	ifconfig | grep HW
	echo
	is_mac_public
	is_mac_local
	sudo cp $gp/10-network.rules /etc/udev/rules.d/10-network.rules
	clear
	echo	
	echo "Ha terminado la configuracion de sus interfaces"
	echo "Reinicie su servidor y ejecute nuevamente gateproxy.sh"
	echo
	echo "Importante:"
	echo "Gateproxy trabaja con NIC-Ethernet. Si eligió una interfaz WiFi"
    	echo "edite /etc/udev/rules.d/10-network.rules antes de reiniciar su"
	echo "servidor y reemplace en KERNEL en* por wl* en la interfaz WiFi"
	echo
	exit 
  fi
}
is_interfaces

clear
echo
echo "  Bienvenido a la instalacion de GateProxy Server (v1.0 Alpha)"
echo
echo "  Requisitos Mínimos:"
echo "  GNU/Linux:    Ubuntu 16.04.x LTS x64"
echo "  Procesador:   Intel compatible 1x GHz"
echo "  Interfaces:   eth0, eth1"
echo "  RAM:          4GB"
echo "  DD:           200 GB"
echo "  Internet:     High Speed"
echo "  Desktop:      Mate (opcional)"
echo "  Dependencias: sudo apt-get -y install git apt dpkg"
echo
echo
echo "  Exención de responsabilidad:
  Este script puede dañar su sistema si se usa incorrectamente.
  Para mayor información, visite gateproxy.com y lea el HowTO"
echo
echo
echo "  Presione ENTER para iniciar o CTRL+C para cancelar";
read RES
clear
echo
echo "Verificando suma..."
a=$(md5sum $gp/gateproxy.tar.gz | awk '{print $1}')
b=$(cat $gp/gateproxy.md5 | awk '{print $1}')
	if [ "$a" = "$b" ]
  then 
   	echo "la suma coincide"
   	tar -C gateproxy -xvzf $gp/gateproxy.tar.gz >/dev/null 2>&1 && sleep 2
   	sudo mkdir -p /etc/acl 2>&1
   	sudo cp -rf $gp/acl/* /etc/acl >/dev/null 2>&1 && sleep 2
   	echo OK
  else
   	echo "la suma no coincide"
   	echo "Verifique su conexion a internet y reinicie el script"
   	rm -rf gateproxy*
	exit
fi

# sincronizando hora y backup crontab, source.list
	sudo hwclock -w >/dev/null 2>&1
	sudo cp /etc/crontab{,.bak} >/dev/null 2>&1
	sudo crontab /etc/crontab >/dev/null 2>&1
	sudo cp /etc/apt/sources.list{,.bak} >/dev/null 2>&1
	sudo touch /var/log/alert.log

# CAMBIANDO NOMBRE DE SERVIDOR EN LOS ARCHIVOS DE CONFIGURACION
function is_hostname(){
	is_name=`echo $HOSTNAME`
	if [ "$is_name" ]; then
	find $gp/conf -type f -print0 | xargs -0 -I "{}" sed -i "s:gateproxy:$is_name:g"  "{}"
   fi
}
is_hostname

# CAMBIANDO NOMBRE DE LA CUENTA DE USUARIO EN LOS ARCHIVOS DE CONFIGURACION
function is_username(){
	is_user=`echo $USER`
	if [ "$is_user" ]; then
	find $gp/conf -type f -print0 | xargs -0 -I "{}" sed -i "s:tu_usuario:$is_user:g"  "{}"
   fi
}
is_username

## CAMBIANDO PARAMETROS DEL SERVIDOR ##
is_ask() {
    pregunta="$1"
    respuesta_incorrecta="$2"
    funcion="$3"

    while true; do
      read -p "$pregunta: " answer
      case $answer in
            [Ss]* )
             	# execute command yes
		    while true; do
            	answer=`$funcion`
            	if [ "$answer" ]; then
            	    echo $answer
            	    	break;
            	 else
            	    echo "$respuesta_incorrecta"
            	 fi
             done;
			break;;
          	[Nn]* )
		# execute command no
			break;;
        * ) echo; echo "Por favor responda SI (s) o NO (n).";;
    esac
done
}

# IP-GATEWAY
function is_ip(){
	read -p "Introduzca la nueva IP (Ejemplo: 192.168.0.10): " IP
	IPNEW=`echo $IP | egrep '^(([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$'`
	if [ "$IPNEW" ]; then
	find $gp/conf -type f -print0 | xargs -0 -I "{}" sed -i "s:192.168.0.10:$IPNEW:g"  "{}"
	echo "Ha introducido correctamente la IP $IP"
   fi
}

# MASCARA
function is_mask1(){
	read -p "Introduzca la nueva mascara de red (Ejemplo: 255.255.255.0): " MASK1
	MASKNEW1=`echo $MASK1 | egrep '^(([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$'`
	if [ "$MASKNEW1" ]; then
	find $gp/conf -type f -print0 | xargs -0 -I "{}" sed -i "s:255.255.255.0:$MASKNEW1:g"  "{}"
	echo "Ha introducido correctamente la mascara $MASK1"
   fi
}

function is_mask2(){
	read -p "Introduzca la nueva mascara de subred (Ejemplo: 24): " MASK2
	MASKNEW2=`echo $MASK2 | egrep '[0-9]'`
	if [ "$MASKNEW2" ]; then
	find $gp/conf -type f -print0 | xargs -0 -I "{}" sed -i "s:/24:/$MASKNEW2:g"  "{}"
	echo "Ha introducido correctamente la mascara $MASK2"
   fi
}

# DNS
function is_dns1(){
	read -p "Introduzca el DNS1 (Ejemplo: 8.8.8.8): " DNS1
	DNSNEW1=`echo $DNS1 | egrep '^(([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$'`
	if [ "$DNSNEW1" ]; then
	find $gp/conf -type f -print0 | xargs -0 -I "{}" sed -i "s:8.8.8.8:$DNSNEW1:g"  "{}"
	echo "Ha introducido correctamente el DNS1 $DNS1"
   fi
}

function is_dns2(){
	read -p "Introduzca el DNS2 (Ejemplo: 8.8.4.4): " DNS2
	DNSNEW2=`echo $DNS2 | egrep '^(([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$'`
	if [ "$DNSNEW2" ]; then
	find $gp/conf -type f -print0 | xargs -0 -I "{}" sed -i "s:8.8.4.4:$DNSNEW2:g"  "{}"
	echo "Ha introducido correctamente DNS2 $DNS2"
   fi
}

# LOCALNET
function is_localnet(){
	read -p "Introduzca el nuevo localnet-network (Ejemplo: 192.168.0.0): " LOCALNET
	LOCALNETNEW=`echo $LOCALNET | egrep '^(([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$'`
	if [ "$LOCALNETNEW" ]; then
	find $gp/conf -type f -print0 | xargs -0 -I "{}" sed -i "s:192.168.0.0:$LOCALNETNEW:g"  "{}"
	echo "Ha introducido correctamente el nuevo localnet-network $LOCALNET"
   fi
}

# BROADCAST
function is_broadcast(){
	read -p "Introduzca el nuevo broadcast (Ejemplo: 192.168.0.255): " BROADCAST
	BROADCASTNEW=`echo $BROADCAST | egrep '^(([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$'`
	if [ "$BROADCASTNEW" ]; then
	find $gp/conf -type f -print0 | xargs -0 -I "{}" sed -i "s:192.168.0.255:$BROADCASTNEW:g"  "{}"
	echo "Ha introducido correctamente el broadcast $BROADCAST"
   fi
}

# INTERFAZ RED LOCAL
function is_eth(){
	read -p "Introduzca la nueva interfaz DHCP para la Red Local (Ejemplo: 1): " ETH
	ETHNEW=`echo $ETH | egrep '[0-9]'` # '^([0-9])$'`
	if [ "$ETHNEW" ]; then
	find $gp/conf -type f -print0 | xargs -0 -I "{}" sed -i "s:eth1:eth$ETHNEW:g"  "{}"
	echo "Ha introducido correctamente la interfaz DHCP $ETH"
   fi
}

# RANGO DHCP
function is_rangeini(){
	read -p "Introduzca la nueva ip inicial rango-dhcp (Ejemplo: 192.168.0.100): " RANGEINI
	RANGEININEW=`echo $RANGEINI | egrep '^(([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$'`
	if [ "$RANGEININEW" ]; then
	find $gp/conf -type f -print0 | xargs -0 -I "{}" sed -i "s:192.168.0.100:$RANGEININEW:g"  "{}"
	echo "Ha introducido correctamente la ip $RANGEINI"
   fi
}

function is_rangefin(){
	read -p "Introduzca la nueva ip final rango-dhcp (Ejemplo: 192.168.0.250): " RANGEFIN
	RANGEFINNEW=`echo $RANGEFIN | egrep '^(([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$'`
	if [ "$RANGEFINNEW" ]; then
	find $gp/conf -type f -print0 | xargs -0 -I "{}" sed -i "s:192.168.0.250:$RANGEFINNEW:g"  "{}"
	echo "Ha introducido correctamente la ip $RANGEFIN"
   fi
}

clear
echo
while true; do
	read -p "Parametros del servidor:
ip 192.168.0.10, mask 255.255.255.0 /24, DNS 8.8.8.8,8.8.4.4, eth1
localnet 192.168.0.0, broadcast 192.168.0.255, rango-dhcp 100-250
Desea cambiar estos parametros? (s/n)" answer
		case $answer in
          [Ss]* )
		# execute command yes
	is_ask "Desea cambiar la IP 192.168.0.10? (s/n)" "Ha introducido una IP incorrecta" is_ip
	is_ask "Desea cambiar la mascara 255.255.255.0? (s/n)" "Ha introducido una mascara incorrecta" is_mask1
	is_ask "Desea cambiar la mascara /24? (s/n)" "Ha introducido una mascara incorrecta" is_mask2
	is_ask "Desea cambiar el DNS1 8.8.8.8? (s/n)" "Ha introducido DNS1 incorrecto" is_dns1
	is_ask "Desea cambiar el DNS2 8.8.4.4? (s/n)" "Ha introducido DNS2 incorrecto" is_dns2
	is_ask "Desea cambiar el localnet 192.168.0.0? (s/n)" "Ha introducido localnet incorrecto" is_localnet
	is_ask "Desea cambiar el broadcast 192.168.0.255? (s/n)" "Ha introducido un broadcast incorrecto" is_broadcast
	is_ask "Desea cambiar interfaz DHCP para la Red Local eth1? (s/n)" "Ha introducido una interfaz incorrecta" is_eth
	is_ask "Desea cambiar el rango DHCP inicial 192.168.0.100? (s/n)" "Ha introducido una ip incorrecta" is_rangeini
	is_ask "Desea cambiar el rango DHCP final 192.168.0.250? (s/n)" "Ha introducido una ip incorrecta" is_rangefin
	echo OK
			break;;
          	[Nn]* )
		# execute command no
			break;;
        * ) echo; echo "Por favor responda SI (s) o NO (n).";;
    esac
done

# LOCALEPURGE (IDIOMAS)
clear
echo
while true; do
	read -p "Se eliminaran todos los idiomas, menos espanol-ingles
Para agregar mas idiomas, edite /etc/locale.nopurge
Desea instalar localepurge? (s/n)" answer
    	case $answer in
          [Ss]* )
		# execute command yes
	sudo cp -f $gp/conf/locale.nopurge /etc
	sudo apt -f install && sudo apt-get -y install localepurge && sudo apt -f install
	sudo localepurge && sudo locale-gen
	echo OK
			break;;
          	[Nn]* )
		# execute command no
			break;;
        * ) echo; echo "Por favor responda SI (s) o NO (n).";;
    esac
done

clear
echo
echo "Eliminando servicios no esenciales..."
gsettings set com.canonical.Unity.Lenses disabled-scopes "['more_suggestions-amazon.scope', 'more_suggestions-u1ms.scope', 'more_suggestions-populartracks.scope', 'music-musicstore.scope', 'more_suggestions-ebay.scope', 'more_suggestions-ubuntushop.scope', 'more_suggestions-skimlinks.scope']" && sleep 1 && gsettings set com.canonical.desktop.interface scrollbar-mode normal >/dev/null 2>&1
sudo update-desktop-database
echo OK
echo
echo
# LIMPIEZA Y ACTUALIZACION
updateandclean(){
	echo "Su sistema se esta actualizando..."
	sudo apt update && sleep 1 && sudo apt -y upgrade && sudo apt -y dist-upgrade && sleep 1 && sudo apt install --fix-missing -y && sleep 1 && sudo apt -f install && sudo fc-cache && sleep 1 && sudo sync && sleep 1 && sudo sysctl -w vm.drop_caches=3 vm.swappiness=20 && sleep 1 && sudo apt -y autoremove && sleep 1 && sudo apt -y autoclean && sleep 1 && sudo apt -y clean && sleep 1 && sudo dpkg --configure -a && sleep 1 && sudo apt -f install
	echo "Su sistema se ha actualizado"
}
updateandclean

# MODULOS ESENCIALES
clear
echo
echo "Instalando Modulos Esenciales..."
echo
	# Google Chrome http://www.google.com/linuxrepositories/  .gnupg/gpg.conf
	#wget -q -O - https://dl.google.com/linux/linux_signing_key.pub | sudo apt-key add -
	wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | sudo apt-key add - && sleep 1 && sudo sh -c 'echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" > /etc/apt/sources.list.d/google-chrome.list' && sleep 1 && sudo gpg --keyserver keys.gnupg.net --recv-key A040830F7FAC5991 && sleep 1 && sudo gpg --export --armor $PUBKRY | sudo apt-key add -
	# Firefox
	sudo sh -c 'echo "deb http://ppa.launchpad.net/ubuntu-mozilla-security/ppa/ubuntu $(lsb_release -sc) main" >> /etc/apt/sources.list' && sleep 1 && sudo gpg --keyserver keys.gnupg.net --recv-key A6DCF7707EBC211F && sleep 1 && sudo gpg --export --armor $PUBKRY | sudo apt-key add -
	# Webmin
	sudo sh -c 'echo "deb http://download.webmin.com/download/repository sarge contrib" >> /etc/apt/sources.list' && wget -q http://www.webmin.com/jcameron-key.asc -O- | sudo apt-key add -
	# GetDeb Apps (Freefilesync, ubuntu-tweak, etc) http://www.getdeb.net/updates/ubuntu/16.04/
	wget -q -O - http://archive.getdeb.net/getdeb-archive.key | sudo apt-key add - && sleep 1 && sudo sh -c 'echo "deb http://archive.getdeb.net/ubuntu $(lsb_release -sc)-getdeb apps" >> /etc/apt/sources.list.d/getdeb.list' && sleep 1 && sudo gpg --keyserver keys.gnupg.net --recv-key 46D7E7CF && sleep 1 && sudo gpg --export --armor $PUBKRY | sudo apt-key add -
	# Systemback
	sudo add-apt-repository ppa:nemh/systemback --yes
    # Remove sendmail
	sudo service sendmail stop >/dev/null 2>&1 && sudo update-rc.d -f sendmail remove
	# Pack Install
	sudo apt update && sudo apt -f install && sudo apt -y install build-essential checkinstall cdbs devscripts dh-make fakeroot libxml-parser-perl check avahi-daemon automake make dpatch patchutils autotools-dev debhelper quilt xutils lintian cmake libtool autoconf git git-core subversion bzr gcc patch module-assistant libupnp-dev dkms linux-headers-$(uname -r) rcconf dialog aptitude bleachbit gksu libgksu2-0 vmm libglib2.0-0 ntfs-config dconf-editor dconf-tools jfsutils sysinfo hardinfo deborphan gtkorphan xsltproc lshw-gtk gedit curl uudeview bluefish geany gparted xfsprogs reiserfsprogs reiser4progs kpartx dmraid util-linux preload prelink synaptic perl libwww-perl libmailtools-perl libmime-lite-perl librrds-perl libdbi-perl libxml-simple-perl libhttp-server-simple-perl libconfig-general-perl libio-socket-ssl-perl libdate-manip-perl libclass-dbi-mysql-perl libnet-ssleay-perl libauthen-pam-perl libpam-runtime libio-pty-perl apt-show-versions python python-pcapy python-cairo python-gi python-gobject python-gobject-2 python-gtk2 python-notify python-dev python-glade2 unattended-upgrades gnome-disk-utility gdebi gdebi-core unace zip unzip p7zip-full sharutils mpack arj cabextract rar unrar file-roller ipset vim ttf-dejavu hfsplus hfsprogs hfsutils hfsutils-tcltk exfat-fuse exfat-utils zenity w3m lsscsi winbind fping freefilesync p7zip-rar linux-tools-common searchmonkey ppa-purge google-chrome-stable webmin firefox snapd systemback systemback-locales unetbootin ubuntu-tweak rrdtool procps geoip-database ipcalc ttf-mscorefonts-installer dmidecode libsasl2-modules postfix postfix-mysql postfix-doc mailutils && sudo apt -f install && sudo dpkg --configure -a && sudo apt -f install && sudo m-a prepare
	sudo cp -f /etc/postfix/master.cf{,.bak} >/dev/null 2>&1
	sudo cp -f $gp/conf/mail/master.cf /etc/postfix/master.cf
	sudo cp -f /etc/postfix/main.cf{,.bak} >/dev/null 2>&1
	sudo cp -f $gp/conf/mail/main.cf /etc/postfix/main.cf
	echo OK

updateandclean

# SERVERS
clear
echo
function is_servers(){
	echo "Instalando Servidores Apache2, DHCP, Squid, PHP7..."
	sudo apt -f install && sudo apt -y install apache2 apache2-doc apache2-utils apache2-dev apache2-suexec-pristine libaprutil1 libaprutil1-dev isc-dhcp-server && sudo apt -f install
	sudo cp -f /etc/apache2/apache2.conf{,.bak} >/dev/null 2>&1
	sudo cp -f $gp/conf/apache/apache2.conf /etc/apache2/apache2.conf
	sudo apache2ctl configtest
	echo OK
	echo
	sudo add-apt-repository ppa:ondrej/php --yes
	sudo apt-get install -y language-pack-en-base python-software-properties
	sudo apt update && sudo apt -f install && sudo apt -y install sudo apt-get install php7.0 php7.0-common php7.0-mysql libmcrypt-dev mcrypt php7.0-mcrypt php7.0-gd php-xml php-xml-parser php7.0-curl php-soap libapr1 libaprutil1 libaprutil1-dbd-sqlite3 libaprutil1-ldap php7.0-mysql php7.0-dev php-pear libapache2-mod-php php-gettext php-xml php-soap php-mcrypt && sudo apt -f install
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
echo "Activacion del Proxy..."
echo
function is_port(){
	read -p "Introduzca el nuevo puerto del proxy (Ejemplo: 3128): " PORT
	PORTNEW=`echo $PORT | egrep '[1-9]'`
	if [ "$PORTNEW" ]; then
	find $gp/conf -type f -print0 | xargs -0 -I "{}" sed -i "s:3128:$PORTNEW:g"  "{}"
	echo "Ha introducido correctamente el puerto del proxy $PORT"
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
	echo "Configure la url de autoconfiguracion del proxy Ej: http://192.168.0.10:8000/proxy.pac"
}

while true; do
	read -p "Configuracion del Proxy Squid y Firewall Iptables
Importante: Se recomienda Proxy No-Transparente (n)

Seleccione s para activar Proxy Transparente (NAT 8080) y filtrado 443
Seleccione n para activar Proxy No-Transparente (3128) y WPAD-PAC (s/n)" answer
		case $answer in
          [Ss]* )
		# execute command yes
	echo	
	is_intercept
	echo OK
			break;;
          [Nn]* )
		# execute command no
	echo
	is_ask "Desea cambiar el puerto del proxy 3128? (s/n)" "Ha introducido un puerto incorrecto" is_port
	echo
	is_proxy
	echo OK
			break;;
        * ) echo; echo "Por favor responda SI (s) o NO (n).";;
    esac
done

# REPORTES, LOGS Y MONITOREO
clear
echo
function is_top(){
	echo "Instalando Top Family (Htop, Apachetop, iotop, Ntop-ng), nethogs y nload"
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
	service ntopng start
	echo "<--| Ntopng fue iniciado el $date |-->" >> /var/log/alert.log
	fi
	date=`date +%d/%m/%Y" "%H:%M:%S`
	#
	if [[ `ps -A | grep redis-server` != "" ]];then
	echo -e "\nONLINE"
	else
	echo -e "\n"
	service redis-server start
	echo "<--| redis-server fue iniciado el $date |-->" >> /var/log/alert.log
	fi'>> $gp/conf/scripts/servicesreload.sh
	echo OK
	echo "Acceda al reporte Ntop-ng en: http://localhost:3000 user: admin pass: admin"
	echo
}

function is_sqstat(){
	echo "Instalando Reportes SQSTAT..."
	sudo tar -xf $gp/conf/monitor/sqstat-1.20.tar.gz
	sudo mkdir -p /var/www/html/sqstat
	sudo cp -f -R sqstat-1.20/* /var/www/html/sqstat/
	sudo cp -f $gp/conf/monitor/config.inc.php /var/www/html/sqstat/config.inc.php
	sudo rm -R sqstat-1.20
	echo OK
	echo "Acceda al reporte Sqstat en: http://localhost/sqstat/sqstat.php"
	echo
}

function is_sarg(){
	echo "Instalando Reportes SARG..."
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
	echo "Acceda al reporte Sarg en: http://192.168.0.10:11500"
	echo "Agregar nombres de usuarios en: /etc/sarg/usertab (192.168.0.10 GATEPROXY)"
	echo
}

function is_iptraf(){
	echo "Instalando Iptraf..."
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
	killall iptraf
	iptraf -i all -L /var/log/iptraf/ip_traffic-1.log -B
	service apache2 restart
	echo "<--| Iptraf fue iniciado el $date |-->" >> /var/log/alert.log
	fi'>> $gp/conf/scripts/servicesreload.sh
	echo OK
	echo "Acceda al reporte Iptraf en: http://192.168.0.10:11300/iptrafaudit.log"
	echo
}

function is_monitor(){
	echo "Instalando Webalizer y Monitorix..."
	sudo sh -c 'echo "deb http://apt.izzysoft.de/ubuntu generic universe" >> /etc/apt/sources.list' && wget -q http://apt.izzysoft.de/izzysoft.asc -O- | sudo apt-key add -
	sudo apt update && sudo apt -f install && sudo apt -y install webalizer monitorix && sudo apt -f install
	sudo mkdir -p /var/www/html/webalizer
	sudo cp -f /etc/webmin/webalizer/config{,.bak} >/dev/null 2>&1
	sudo cp -f $gp/conf/monitor/config /etc/webmin/webalizer/config
	sudo cp -f /etc/webalizer/webalizer.conf{,.bak} >/dev/null 2>&1
	sudo cp -f $gp/conf/monitor/webalizer.conf /etc/webalizer/webalizer.conf
	sudo cp -f /etc/monitorix/monitorix.conf{,.bak} >/dev/null 2>&1
	sudo cp -f $gp/conf/monitor/monitorix.conf /etc/monitorix/monitorix.conf
	echo "Introduzca su contrasena para Monitorix..."
	sudo htpasswd -d -c /var/lib/monitorix/htpasswd $USER
	sed -i '/MONITORIX/r $gp/conf/monitor/iptmonitorix.txt' $gp/conf/scripts/iptables.sh
	echo '# Monitorix Service
	date=`date +%d/%m/%Y" "%H:%M:%S`
	if [[ `ps -A | grep monitorix-httpd` != "" ]];then
	echo -e "\nONLINE"
	else
	echo -e "\n"
	service monitorix start && service apache2 restart
	echo "<--| Monitorix fue iniciado el $date |-->" >> /var/log/alert.log
	fi'>> $gp/conf/scripts/servicesreload.sh
	echo OK
	echo "Acceda al reporte Monitorix en: http://localhost:8081/monitorix/"
	echo
}

function is_bandwidthd(){
	echo "Instalando Bandwidthd Monitor..."
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
	/etc/init.d/bandwidthd start && service apache2 restart
	echo "<--| Bandwidthd fue iniciado el $date |-->" >> /var/log/alert.log
	fi'>> $gp/conf/scripts/servicesreload.sh
	echo OK
	echo "Acceda al reporte Bandwidthd en: http://192.168.0.10:11400"
	echo
}

function is_speedtest(){
	echo "Instalando Speedtest..."
	sudo apt -y install python-pip && sudo apt -f install && sudo pip install --upgrade pip && sudo pip install speedtest-cli
	echo OK
	echo "Test de ancho de banda, abra el terminal y escriba: speedtest"
	echo
}

function is_netdata(){
	echo "Instalando Netdata..."
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
	/usr/sbin/netdata
	echo "<--| NetData fue iniciado el $date |-->" >> /var/log/alert.log
	fi'>> $gp/conf/scripts/servicesreload.sh
	echo OK
	echo "Acceda al Netdata en: http://localhost:19999/"
}

function is_logs(){
	echo "Instalando Logwatch, Logrotate, Ulogd2, logtail, Awstats..."
	sudo apt -y install logwatch logrotate ulogd2 acct awstats logtail && sudo apt -f install
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
	echo OK
	echo
}

while true; do
    read -p "Desea instalar los Modulos de Reportes, Logs y Monitoreo? (recomendado)
Sqstat, NetData, Iptraf, nethogs, Webalizer, Monitorix, Bandwidthd, Speedtest,
nload, Sarg, Top Family, Logwatch, Logrotate, Ulogd2, logtail, Awstats (s/n)" answer
		case $answer in
          [Ss]* )
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
	echo OK
			break;;
          	[Nn]* )
		# execute command no
			break;;
        * ) echo; echo "Por favor responda SI (s) o NO (n).";;
    esac
done

# MODULOS OPCIONALES
clear
echo

function is_mate(){
# Mate Desktop
clear
echo
# MATE DESKTOP
is_mate=`which mate-panel`
    if [ "$is_mate" ]; then
        echo "Mate Desktop ya esta instalado"
    else
        while true; do
        read -p "Desea instalar Mate Desktop? (s/n)" answer
    	case $answer in
          [Ss]* )
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
        * ) echo; echo "Por favor responda SI (s) o NO (n).";;
    esac
done
fi
}

function is_vbox(){
# VirtualBox
clear
echo
while true; do
	read -p "Desea instalar Virtualbox Pack? (s/n)" answer
		case $answer in
          [Ss]* )
		# execute command yes
	echo "Instalando Virtualbox Pack..."
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
	echo "verifique con groups $USER"
	sudo cp -f $gp/conf/virtual/vm /etc/init.d/vm
	sudo chown root:root /etc/init.d/vm
	sudo chmod +x /etc/init.d/vm
	sudo update-rc.d vm defaults 99 01
	echo "Instalando PHPVirtualbox..."
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
	echo "Acceso Local a las VMs: http://192.168.0.10:11600"
	echo
		break;;
          	[Nn]* )
		# execute command no
			break;;
        * ) echo; echo "Por favor responda SI (s) o NO (n).";;
    esac
done
}

function is_gdiskdump(){
# Gdiskdump
clear
echo
while true; do
	read -p "Desea instalar gdiskdump (Disk Clone)? (s/n)" answer
		case $answer in
          [Ss]* )
		# execute command yes
	sudo rm gdiskdump*.deb >/dev/null 2>&1 && sudo apt -y purge gdiskdump >/dev/null 2>&1
	wget -c --retry-connrefused -t 0 https://launchpad.net/gdiskdump/trunk/0.8/+download/gdiskdump_0.8-1_all.deb
	sudo dpkg -i gdiskdump_0.8-1_all.deb && sudo apt -f install
	echo OK
			break;;
          	[Nn]* )
		# execute command no
			break;;
        * ) echo; echo "Por favor responda SI (s) o NO (n).";;
    esac
done
}

function is_remote(){
# Remote Desktop
clear
echo
while true; do
	read -p "Desea instalar Remote Desktop (Teamviewer y Remmina)? (s/n)" answer
		case $answer in
          [Ss]* )
		# execute command yes
	echo "Instalando Remmina..."
	sudo apt -y install remmina && sudo apt -f install
	echo OK
	echo "Instalando Teamviewer..."
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
	teamviewer --daemon start
	echo "<--| Teamviewer fue iniciado el $date |-->" >> /var/log/alert.log
	fi'>> $gp/conf/scripts/servicesreload.sh
	echo OK
		break;;
          	[Nn]* )
		# execute command no
			break;;
        * ) echo; echo "Por favor responda SI (s) o NO (n).";;
    esac
done
}

function is_vnc(){
# VNC Server Remote Desktop
clear
echo
while true; do
	read -p "Desea instalar VNC server (Vino)? (s/n)" answer
		case $answer in
          [Ss]* )
		# execute command yes
	echo
	echo "Instalando VNC Vino-Server..."
	sudo apt -y install vino && sudo apt -f install
	vino-preferences
	sudo cp $gp/conf/vnc/vino-server.sh /etc/init.d/vino-server.sh
	sudo chown root:root /etc/init.d/vino-server.sh
	sudo chmod +x /etc/init.d/vino-server.sh
	echo OK
	echo "Inicie el servidor VNC manualmente con: sudo /etc/init.d/vnc-server.sh start"
		break;;
          	[Nn]* )
		# execute command no
			break;;
        * ) echo; echo "Por favor responda SI (s) o NO (n).";;
    esac
done
}

function is_samba(){
# SAMBA
clear
echo
while true; do
	read -p "Desea instalar samba y activar carpeta compartida
con papelera de reciclaje y auditoria? (s/n)" answer
		case $answer in
          [Ss]* )
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
	service smbd start
	systemctl restart smbd && systemctl restart nmbd
	echo "<--| Samba (smbd) fue iniciado el $date |-->" >> /var/log/alert.log
	fi
	#
	# Samba Service Nmbd
	date=`date +%d/%m/%Y" "%H:%M:%S`
	if [[ `ps -A | grep nmbd` != "" ]];then
	echo -e "\nONLINE"
	else
	echo -e "\n"
	systemctl restart smbd && systemctl restart nmbd
	echo "<--| Samba (nmbd) fue iniciado el $date |-->" >> /var/log/alert.log
	fi
	'>> $gp/conf/scripts/servicesreload.sh
	echo OK
	echo "Acceda al reporte samba en http://192.168.0.10:11200/smbdaudit.log"	
		break;;
          	[Nn]* )
		# execute command no
			break;;
        * ) echo; echo "Por favor responda SI (s) o NO (n).";;
    esac
done
}

while true; do
	read -p "Instalacion de Modulos Opcionales:

Mate Desktop, Virtualbox Pack, gdiskdump, Samba,
Vino server, Remote Desktop (Teamviewer-Remmina)

Desea instalar esos Modulos? (puede elegir cada uno) (s/n)" answer
		case $answer in
          [Ss]* )
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
        * ) echo; echo "Por favor responda SI (s) o NO (n).";;
    esac
done

# MODULOS SE SEGURIDAD AVANZADOS
clear
echo
function is_security(){
while true; do
   read -p "Desea instalar el Pack de Seguridad (Usuarios Avanzados)?
Fail2ban, DDOSDeflate, Mod Security, OWASP, Evasive, Rootkitchk (s/n)" answer
		case $answer in
          [Ss]* )
		# execute command yes
	echo
	echo "Instalando Fail2Ban..."
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
	rm -rf /var/run/fail2ban/fail2ban.sock >/dev/null 2>&1
	service fail2ban start && service rsyslog restart
	echo "<--| Fail2ban fue iniciado el $date |-->" >> /var/log/alert.log
	fi'>> $gp/conf/scripts/servicesreload.sh
	echo OK
	echo "Acceda al reporte fail2ban en: /var/log/fail2ban.log"
	echo
	echo "Instalando DDOS Deflate..."
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
	echo "Instalado Mod Security..."
	sudo apt -f install && sudo apt -y install libxml2-dev liblua5.1-0 lua5.1 libxml2 libcurl3 libcurl3-dev libxml2-utils libapache2-mod-evasive libapache2-modsecurity libapache2-mod-security2 modsecurity-crs && sudo dpkg --configure -a && sudo apt -f install
	sudo ln -sf /usr/lib/x86_64-linux-gnu/libxml2.so.2 /usr/lib/libxml2.so.2 >/dev/null 2>&1
	echo "Apache hardening..."
	sudo cp -f /etc/apache2/conf-enabled/security.conf{,.bak} >/dev/null 2>&1
	sudo cp -f $gp/conf/apache/security.conf /etc/apache2/conf-enabled/security.conf
	echo OK
	echo "Configure headers..."
	sudo ln -s /etc/apache2/mods-available/headers.load /etc/apache2/mods-enabled/headers.load
	echo "Enable mod_unique_id, rewrite and expires modules..."
	sudo a2enmod unique_id && sudo a2enmod rewrite && sudo a2enmod expires && sudo service apache2 restart
	echo "Configure ModSecurity..."
	sudo cp -f /etc/modsecurity/modsecurity.conf{,.bak} >/dev/null 2>&1
	sudo cp -f $gp/conf/apache/modsecurity.conf /etc/modsecurity/modsecurity.conf
	# modsecurity anomalies 
	# sudo cp $gp/conf/apache/modsecurity_crs_21_protocol_anomalies.conf /etc/apache2/mod-security/modsecurity_crs_21_protocol_anomalies.conf
	echo
	echo "Instalando OWASP..."
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
	echo "Reiniciando servicios y verificando..."
	sudo a2enmod headers && sudo a2enmod evasive && sudo a2enmod security2 && sudo service apache2 restart
	sudo apachectl -M | grep security2
	sudo apachectl -M | grep evasive
	sudo apache2ctl configtest
	echo "Mensaje Correcto: security2_module (shared),evasive20_module (shared),Syntax OK"
	echo OK
	echo "Verifique errores y falsos positivos con: tail /var/log/apache2/error.log"
	echo
	echo "Instalando Rootkit checkers..."
	sudo apt -f install && sudo apt -y install rkhunter chkrootkit && sudo apt -f install
	sudo rkhunter --update
	sudo cp -f /etc/chkrootkit.conf{,.bak} >/dev/null 2>&1
	sudo cp -f $gp/conf/apache/chkrootkit.conf /etc/chkrootkit.conf
	sudo cp -f /etc/default/rkhunter{,.bak} >/dev/null 2>&1
	sudo cp -f $gp/conf/apache/rkhunter /etc/default/rkhunter
	sudo crontab -l | { cat; echo "@weekly /usr/bin/rkhunter --cronjob --update --quiet"; } | sudo crontab -
	echo "Verifique el reporte en /var/log/rkhunter.log"
	echo OK
	echo
			break;;
          	[Nn]* )
		# execute command no
			break;;
        * ) echo; echo "Por favor responda SI (s) o NO (n).";;
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
   read -p "NIPS/NIDS in Docker (Experimental)
Desea instalar Snort? (with Barnyard2, PulledPork, Snorby) (s/n)" answer
		case $answer in
          [Ss]* )
		# execute command yes
	echo "Instalando Docker..."
	sudo apt-key adv --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys 58118E89F3A912897C070ADBF76221572C52609D
	echo "deb https://apt.dockerproject.org/repo ubuntu-xenial main" | sudo tee /etc/apt/sources.list.d/docker.list
    sudo apt update && sudo apt -f install && sudo apt -y install docker-engine
	sudo usermod -aG docker $(whoami)
	sudo systemctl enable docker && sudo systemctl start docker
	echo "Vea comparativa VBox vs Docker en goo.gl/8FfC8O"
	echo
	echo "Instalando Snort, Barnyard2, PulledPork, Snorby..."
	git clone https://github.com/amabrouki/snort.git
	cd snort && sudo docker build -t snort . && cd
	echo OK
	echo "Iniciar con: docker run  --privileged -it -p 3000:3000 -d snort"
	echo "Vea las instrucciones en: https://github.com/amabrouki/snort"
			break;;
          	[Nn]* )
		# execute command no
			break;;
        * ) echo; echo "Por favor responda SI (s) o NO (n).";;
    esac
done
}

function is_clamav(){
# ANTIVIRUS
clear
echo
while true; do
   read -p "Desea instalar ClamAV-AntiVirus (Min 1GB RAM)? (s/n)" answer
		case $answer in
          [Ss]* )
		# execute command yes
	echo
	echo "Instalando ClamAV..."
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
	echo "<--| Clamav fue iniciado el $date |-->" >> /var/log/alert.log
	fi
	#
	if [[ `ps -A | grep freshclam` != "" ]];then
	echo -e "\nONLINE"
	else
	echo -e "\n"
	service clamav-freshclam start
	echo "<--| Clamav Update fue iniciado el $date |-->" >> /var/log/alert.log
	fi'>> $gp/conf/scripts/servicesreload.sh
	echo OK
	echo "Elimine malware con: sudo clamscan --infected --remove --recursive /home"
	echo OK
	echo
			break;;
          	[Nn]* )
		# execute command no
			break;;
        * ) echo; echo "Por favor responda SI (s) o NO (n).";;
    esac
done
}

function is_pass(){
# PASSWORD
clear
echo
while true; do
    read -p "Desea instalar pack de cifrado y contrasenas? (Usuarios Avanzados)
libpam-cracklib, 2-Factor Google Authentication y Veracrypt (s/n)" answer
		case $answer in
          [Ss]* )
		# execute command yes
	sudo apt -f install && sudo apt -y install libpam-cracklib
	sudo cp -f /etc/pam.d/common-password{,.bak} >/dev/null 2>&1
	sudo cp -f $gp/conf/security/common-password /etc/pam.d/common-password
	sudo apt -f install && sudo apt -y libpam-google-authenticator
	sudo cp -f /etc/pam.d/common-auth{,.bak} >/dev/null 2>&1
	sudo cp -f $gp/conf/security/common-auth /etc/pam.d/common-auth
	sudo add-apt-repository ppa:unit193/encryption --yes
    sudo apt update && sudo apt -f install && sudo apt -y install veracrypt
	echo OK
			break;;
          	[Nn]* )
		# execute command no
			break;;
        * ) echo; echo "Por favor responda SI (s) o NO (n).";;
    esac
done
}

function is_audit(){
# AUDITORIA
clear
echo
while true; do
    read -p "Desea instalar herramientas de Red y Auditoria? (Usuarios Avanzados) 
Lynis, Nmap, Zenmap, ArpScan, python-nmap, Pipe Viewer, SSlscan, nbtscan,
cutter, wireshark, Hping, tcpdump, NetDiscover, My traceroute, Networking,
toolkit, Byobu, dsniff y wireless-tools (s/n)" answer
		case $answer in
          [Ss]* )
		# execute command yes
	sudo apt -f install && sudo apt -y install cutter wireshark nmap zenmap python-nmap lynis arp-scan hping3 pv net-tools mtr-tiny grc wireless-tools sslscan byobu traceroute nbtscan tcpdump dsniff && sudo apt -f install
	echo OK
			break;;
          	[Nn]* )
		# execute command no
			break;;
        * ) echo; echo "Por favor responda SI (s) o NO (n).";;
    esac
done
}

while true; do
	read -p "Modulo de Seguridad, Cifrado y Auditoria (Usuarios Avanzados):

Fail2Ban, DDOS Deflate, Mod Security, OWASP, Mod evasive, Rootkit checkers,
Snort with Barnyard2, PulledPork, Snorby in Docker, ClamAV, libpam-cracklib,
2-Factor GoogleAuth, Veracrypt, Lynis, Nmap, Zenmap, ArpScan, SSLscan, cutter
python-nmap, Pipe Viewer, nbtscan, wireshark, Hping, tcpdump, dsniff, Byobu
My traceroute, Networking, toolkit, NetDiscover y wireless-tools

Desea instalar este Modulo? (puede elegir cada uno) (s/n)" answer
		case $answer in
          [Ss]* )
		# execute command yes
	is_security
	is_ids
	is_clamav
	is_pass
	is_audit
	echo OK
			break;;
          	[Nn]* )
		# execute command no
			break;;
        * ) echo; echo "Por favor responda SI (s) o NO (n).";;
    esac
done

# MODULO DNS
clear
echo
function is_dnsmasq(){
while true; do
	read -p "Modulo DNS-LOCAL (Usuarios Avanzados):
Desea instalar dnsmasq, desactivar resolvconf y restaurar resolv.conf? (s/n)" answer
		case $answer in
          [Ss]* )
		# execute command yes
	echo "Instalando DNS-LOCAL dnsmasq..."
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
	/etc/init.d/dnsmasq start
	echo "<--| dnsmasq fue iniciado el $date |-->" >> /var/log/alert.log
	fi'>> $gp/conf/scripts/servicesreload.sh
	echo OK
	echo
	echo "Desactivando resolvconf y restaurando resolv.conf..."
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
        * ) echo; echo "Por favor responda SI (s) o NO (n).";;
    esac
done
}
is_dnsmasq

# VPN-SSH
function is_vpnssh(){
clear
echo
while true; do
   read -p "Desea instalar el modulo VPN-SSH (Usuarios Avanzados)
4nonimizer, FruhoVPN, OpenVPN, OpenSSH? (s/n)" answer
		case $answer in
          [Ss]* )
		# execute command yes
	echo
	git clone https://github.com/Hackplayers/4nonimizer.git
	sudo chmod +x 4nonimizer/4nonimizer && sudo 4nonimizer/4nonimizer install
	echo OK
	echo "HowTO https://github.com/Hackplayers/4nonimizer"
	echo
    echo "Instalando FruhoVPN..."
	sudo rm fruho*.deb && sudo apt -y purge fruho >/dev/null 2>&1
	last=$(wget -O - https://github.com/fruho/fruhoapp/releases | grep -Po '/[^"]+download[^"]+' | grep deb | grep amd64 | sort | tail -1)
	wget https://github.com$last -O fruho.deb
	sudo dpkg -i fruho.deb && sudo apt-get install -f
	echo OK
	echo "Instalando OpenVPN y OpenSSH..."
	sudo apt -f install && sudo apt -y install openvpn curl openssl
	echo
			break;;
          	[Nn]* )
		# execute command no
			break;;
        * ) echo; echo "Por favor responda SI (s) o NO (n).";;
    esac
done
}
is_vpnssh

# BLACKUSB
clear
echo
function is_blackusb(){
while true; do
    read -p "Modulo Experimental (Blackusb Project)
Desea activar la proteccion de puertos usb via udev? (s/n)" answer
		case $answer in
          [Ss]* )
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
        * ) echo; echo "Por favor responda SI (s) o NO (n).";;
    esac
done
}
is_blackusb

# CONFIGURACION
clear
echo
echo "Transfiriendo Proyectos Blackweb, Blackip, Whiteip..."
git clone https://github.com/maravento/blackweb
sudo cp -f blackweb/blackweb.sh /etc/init.d >/dev/null 2>&1
tar -C blackweb -xvzf blackweb/blackweb.tar.gz >/dev/null 2>&1
sudo cp -f blackweb/{blackweb,blackdomains,whitedomains}.txt /etc/acl >/dev/null 2>&1
git clone https://github.com/maravento/blackip.git
sudo cp -f blackip/blackip.sh /etc/init.d >/dev/null 2>&1
sudo cp -f blackip/blackip.txt /etc/acl >/dev/null 2>&1
sudo /etc/init.d/blackip.sh
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
echo "Transfiriendo configuraciones..."
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
echo "Creando contrasena de acceso a /var/www/html..."
echo
sudo cp -f /etc/apache2/sites-enabled/000-default.conf{,.bak} >/dev/null 2>&1
sudo cp -f $gp/conf/apache/000-default.conf /etc/apache2/sites-enabled/000-default.conf
sudo htpasswd -c /etc/apache2/.htpasswd $USER
echo OK
echo
echo "Agregando tareas al crontab..."
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
echo "Eliminando huerfanos..."
sudo deborphan | xargs sudo apt -y remove --purge
sudo deborphan --guess-data | xargs sudo apt -y remove --purge
sudo dpkg --configure -a && sudo apt -f install
echo OK
echo
echo "Actualizacion y Limpieza"
updateandclean
clear
echo
echo "Fin de la instalacion. Presione ENTER para reiniciar";
read RES
mkdir -p .local/share/Trash/files >/dev/null 2>&1
mv -f *.deb gateproxy* *.md5 .local/share/Trash/files >/dev/null 2>&1
history -c
sudo reboot
