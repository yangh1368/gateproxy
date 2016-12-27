## [Gateproxy] (http://www.gateproxy.com)

<a target="_blank" href=""><img src="https://img.shields.io/badge/Development-ALPHA-blue.svg"></a>

[Gateproxy] (http://www.gateproxy.com) es un servidor para administrar pequeñas y medianas redes [LAN] (https://es.wikipedia.org/wiki/Red_de_%C3%A1rea_local), lo más intuitivo y desatendido posible, apto para el manejo del usuario, sin importar si tiene o no un alto grado de conocimientos en GNU/Linux, generando así una mejor experiencia. El script de instalación y configuración es totalmente automatizado y personalizable, de acuerdo a las necesidades del administrador u organización, con una interacción mínima durante proceso, reduciendo así la curva de aprendizaje. Puede ser implementado tanto en un servidor "físico", como en una VM, para mayor flexibilidad y portabilidad.

[Gateproxy] (http://www.gateproxy.com) is a server for managing home & business LANs, and inattentive as intuitive as possible, suitable for handling user, regardless of whether it has a high degree of knowledge in GNU/Linux, thus creating a better experience. The installation and configuration script is fully automated and customizable according to the needs of the administrator or organization, with minimal interaction during the process, thus reducing the learning curve. It can be implemented in either a "physical" server, such as in a VM, for greater flexibility and portability.

### Descripción/Description

- HowTO:        [Gateproxy.pdf] (https://github.com/maravento/gateproxy/raw/master/gateproxy.pdf)
- Version:      1.0 Alpha

### Requisitos Mínimos/Minimum requirements

- GNU/Linux:    [Ubuntu 16.04.x LTS x64] (http://www.ubuntu.com/download)
- Processor:    Intel compatible 1x GHz
- Interfaces:   eth0, eth1
- RAM:          4GB
- DD:           200 GB
- Internet:     High speed (recommended)
- Bash:         4.3x (check with `echo $BASH_VERSION`)
- Desktop:      [Mate] (http://mate-desktop.org/) (Optional)
- Languaje:		eng-spa

### Instalación/Installation

Abra el terminal y ejecute/Open the terminal and run (no-root)

```
$ git clone https://github.com/maravento/gateproxy.git
$ chmod +x gateproxy/gateproxy.sh && gateproxy/gateproxy.sh
```
![Gateproxy](https://2.bp.blogspot.com/-wExMnhIQyHs/WBX9CIDh8cI/AAAAAAAAC2E/BYvutPnjvzQEuIAIkxv_n3LxgBM7sukEwCLcB/s1600/gateproxy.jpg)

### Dependencias/Dependencies

```
git apt dpkg
```

[Ubuntu 16.04.x LTS x64] (http://www.ubuntu.com/download). Upgrade:
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


### Licence

[GPL-3.0] (https://www.gnu.org/licenses/gpl-3.0.en.html)

This Project is educational purposes. Este proyecto es con fines educativos. Agradecemos a todos aquellos que han contribuido a este proyecto. We thank all those who contributed to this project. Special thanks to [novatoz.com] (http://www.novatoz.com)

© 2016 [Gateproxy] (http://www.gateproxy.com) by [maravento] (http://www.maravento.com)

#### Disclaimer

Este script puede dañar su sistema si se usa incorrectamente. Úselo bajo su propio riesgo. This script can damage your system if used incorrectly. Use it at your own risk. [HowTO Gateproxy pdf] (https://github.com/maravento/gateproxy/raw/master/gateproxy.pdf)

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
