## [Gateproxy] (http://www.gateproxy.com)

<a target="_blank" href=""><img src="https://img.shields.io/badge/Development-ALPHA-blue.svg"></a>

[Gateproxy] (http://www.gateproxy.com) es un servidor para administrar pequeñas y medianas redes [LAN] (https://es.wikipedia.org/wiki/Red_de_%C3%A1rea_local), lo más intuitivo y desatendido posible, apto para el manejo del usuario, sin importar si tiene o no un alto grado de conocimientos en GNU/Linux, generando así una mejor experiencia.

El script de instalación y configuración es totalmente automatizado y personalizable, de acuerdo a las necesidades del administrador u organización, con una interacción mínima durante proceso, reduciendo así la curva de aprendizaje. Puede ser implementado tanto en un servidor "físico", como en una VM, para mayor flexibilidad y portabilidad.

[Gateproxy] (http://www.gateproxy.com) is a server for managing home & business LANs, and inattentive as intuitive as possible, suitable for handling user, regardless of whether it has a high degree of knowledge in GNU/Linux, thus creating a better experience.

The installation and configuration script is fully automated and customizable according to the needs of the administrator or organization, with minimal interaction during the process, thus reducing the learning curve. It can be implemented in either a "physical" server, such as in a VM, for greater flexibility and portability.

### Descripción - Description

- HowTO:        [Gateproxy.pdf] (https://goo.gl/ZT4LTi)
- Version:      1.0 Alpha

### Requisitos Mínimos -Minimum requirements

- GNU/Linux:    [Ubuntu 16.04.x LTS x64] (http://www.ubuntu.com/download)
- Processor:    Intel compatible 1x GHz
- Interfaces:   eth0, eth1
- RAM:          4GB
- DD:           200 GB
- Internet:     High speed (recommended)
- Bash:         4.3x (check with `echo $BASH_VERSION`)
- Desktop:      [Mate] (http://mate-desktop.org/) (Optional)
- Languaje:		eng-spa

### Instalación - Installation

Abra el terminal y ejecute (no-root):

Open the terminal and run (no-root):
```
$ git clone https://github.com/maravento/gateproxy.git
$ chmod +x gateproxy/gateproxy.sh && gateproxy/gateproxy.sh
```
![Gateproxy](https://3.bp.blogspot.com/-ihJ9Qt0lYGM/V-AjCh1Jr6I/AAAAAAAACxQ/uyWGtPhP2q8EADyDMke5Nf56T_Nnqr1mgCLcB/s1600/gateproxy.jpg)

### Dependencias - Dependencies

```
sudo apt-get -y install git apt dpkg
```

Upgrade to [Ubuntu 16.04.x LTS x64] (http://www.ubuntu.com/download):
```
sudo do-release-upgrade -d
```

### Own Projects Included

[Blackweb] (https://github.com/maravento/blackweb)

[Blackip] (https://github.com/maravento/blackip)

[Blackstring] (https://github.com/maravento/blackstring)

[Whiteip] (https://github.com/maravento/whiteip)


### Fork Projects Included

[Blackusb] (https://github.com/maravento/blackusb)


### External Projects Included

[4nonimizer] (https://github.com/Hackplayers/4nonimizer)

[Docker: Snort, Barnyard2, PulledPork and Snorby] (https://github.com/amabrouki/snort)

[NetData] (https://github.com/firehol/netdata)

[Owasp-modsecurity-crs] (https://github.com/SpiderLabs/owasp-modsecurity-crs)

[DDoS Deflate] (https://github.com/jgmdev/ddos-deflate)


### Exención de Responsabilidad - Disclaimer

Este script puede dañar su sistema si se usa incorrectamente. Úselo bajo su propio riesgo. This script can damage your system if used incorrectly. Use it at your own risk. [HowTO Gateproxy] (https://goo.gl/ZT4LTi)

### Legal

This Project is educational purposes. Este proyecto es con fines educativos. Agradecemos a todos aquellos que han contribuido a este proyecto. We thank all those who contributed to this project. Special thanks to [novatoz.com] (http://www.novatoz.com)

© 2016 [Gateproxy] (http://www.gateproxy.com) by [maravento] (http://www.maravento.com)
