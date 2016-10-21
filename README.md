## [Gateproxy] (http://www.gateproxy.com)

<a target="_blank" href=""><img src="https://img.shields.io/badge/Development-ALPHA-blue.svg"></a>

[Gateproxy] (http://www.gateproxy.com) es un servidor para administrar pequeñas y medianas redes [LAN] (https://es.wikipedia.org/wiki/Red_de_%C3%A1rea_local), lo más intuitivo y desatendido posible, apto para el manejo del usuario, sin importar si tiene o no un alto grado de conocimientos en GNU/Linux, generando así una mejor experiencia.

El script de instalación y configuración es totalmente automatizado y personalizable, de acuerdo a las necesidades del administrador u organización, con una interacción mínima durante proceso, reduciendo así la curva de aprendizaje. Puede ser implementado tanto en un servidor "físico", como en una VM, para mayor flexibilidad y portabilidad.

### Descripción

- HowTO:        [Gateproxy.pdf] (https://goo.gl/ZT4LTi)
- Version:      1.0 Alpha

### Requisitos Mínimos

- GNU/Linux:    [Ubuntu 16.04.x LTS x64] (http://www.ubuntu.com/download)
- Procesador:   Intel compatible 1x GHz
- Interfaces:   eth0, eth1
- RAM:          4GB
- DD:           200 GB
- Internet:     Alta velocidad (recomendado)
- Bash:         4.3x (verifique con `echo $BASH_VERSION`)
- Desktop:      [Mate] (http://mate-desktop.org/) (Opcional)

### Instalación

Abra el terminal y ejecute (no-root):
```
$ git clone https://github.com/maravento/gateproxy.git
$ chmod +x gateproxy/gateproxy.sh && gateproxy/gateproxy.sh
```
![Gateproxy](https://3.bp.blogspot.com/-ihJ9Qt0lYGM/V-AjCh1Jr6I/AAAAAAAACxQ/uyWGtPhP2q8EADyDMke5Nf56T_Nnqr1mgCLcB/s1600/gateproxy.jpg)

### Dependencias

```
sudo apt-get -y install git apt dpkg
```

Si tiene una versión anterior a [Ubuntu 16.04.x LTS x64] (http://www.ubuntu.com/download), actualice con:
```
sudo do-release-upgrade -d
```

### Proyectos Propios Incluidos

[Blackweb] (https://github.com/maravento/blackweb)

[Blackip] (https://github.com/maravento/blackip)

[Blackstring] (https://github.com/maravento/blackstring)

[Whiteip] (https://github.com/maravento/whiteip)


### Proyectos Fork Incluidos

[Blackusb] (https://github.com/maravento/blackusb)


### Proyectos de Terceros incluidos

[4nonimizer] (https://github.com/Hackplayers/4nonimizer)

[Docker: Snort, Barnyard2, PulledPork and Snorby] (https://github.com/amabrouki/snort)

[NetData] (https://github.com/firehol/netdata)

[Owasp-modsecurity-crs] (https://github.com/SpiderLabs/owasp-modsecurity-crs)


### Exención de Responsabilidad

Este script puede dañar su sistema si se usa incorrectamente. Úselo bajo su propio riesgo. Lea [HowTO Gateproxy] (https://goo.gl/ZT4LTi)

### Legal

This Project is educational purposes. Este proyecto es con fines educativos. Agradecemos a todos aquellos que han contribuido a este proyecto, en especial [novatoz.com] (http://www.novatoz.com)

© 2016 [Gateproxy] (http://www.gateproxy.com) por [maravento] (http://www.maravento.com)
