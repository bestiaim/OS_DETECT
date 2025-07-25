# OS_DETECT
creado por: bestiaim
Script Bash para detectar el sistema operativo remoto utilizando distintas técnicas de fingerprinting activo y pasivo.

## 🛠️ Métodos soportados

1. **Nmap -O**: Detección de SO por huellas TCP/IP.
2. **Nmap -A**: Detección avanzada de SO (incluye servicios y traceroute).
3. **Xprobe2**: Detección por ICMP, más sigilosa.
4. **p0f**: Detección pasiva, ideal para no generar alertas.

## 📦 Requisitos

Debes tener instaladas las siguientes herramientas en tu sistema:

- `nmap`
- `xprobe2`
- `p0f`
- `ping`, `timeout`, `sudo`

## 🔧 Uso

Ejecuta el script con permisos adecuados:

```bash
chmod +x os_detect.sh
./os_detect.sh


EJEMPLO DE METODO DE USO

$ ./os_detect.sh

Ingresa la(s) IP(s) o red/CIDR objetivo (espacio separador): 192.168.1.10
Selecciona el método de detección de SO:
  1) Nmap (-O)
  2) Nmap completo (-A)
  3) Xprobe2
  4) p0f (pasivo con ping automático)
Opción [1-4]: 1

=== Objetivo: 192.168.1.10 ===
Resultado: OS details: Linux 5.4 - 5.10
