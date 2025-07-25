#!/bin/bash
# OS Detect Wrapper – v1.1 (con p0f automatizado)
# -----------------------------------------------
# DESARROLLADO POR https://github.com/bestiaim
# Script enfocado únicamente en la detección de sistema operativo remoto.
# Este script utiliza 4 métodos de detección de sistema operativo remoto:
#
# MÉTODO 1) METHOD="nmap_O" → check_cmd sudo
#   - Herramienta usada: Nmap con opción -O
#   - ¿Qué hace?: Realiza OS detection por huellas TCP/IP (fingerprinting activo).
#   - Analiza el comportamiento de la pila TCP/IP del objetivo.
#   - Requiere privilegios (sudo) para enviar paquetes "raw".
#
# MÉTODO 2) METHOD="nmap_A" → check_cmd sudo
#   - Herramienta usada: Nmap con opción -A
#   - ¿Qué hace?: Activa detecciones avanzadas como:
#     a) OS Detection (-O)
#     b) Detección de servicios (-sV)
#     c) Traceroute
#     d) Scripts NSE
#
# MÉTODO 3) METHOD="xprobe2" → check_cmd xprobe2 + sudo
#   - Herramienta usada: xprobe2
#   - ¿Qué hace?: Fingerprinting activo por paquetes ICMP.
#   - Más sigilosa que Nmap en algunos entornos.
#
# MÉTODO 4) METHOD="p0f_auto" → check_cmd p0f + timeout + sudo
#   - Herramienta usada: p0f
#   - ¿Qué hace?: Fingerprinting pasivo (sin enviar paquetes).
#   - Deduce el sistema operativo observando conexiones TCP.
#   - Muy útil para análisis sigiloso.
#
# --- COMPARATIVA ---
# Método       | Tipo        | Herramienta | Requiere sudo | Intrusividad | Precisión
# -------------|-------------|-------------|---------------|--------------|-----------
# nmap_O       | Activo      | Nmap        | Sí            | Alta         | Alta
# nmap_A       | Activo      | Nmap        | Sí            | Alta         | Muy alta
# xprobe2      | Activo (ICMP)| Xprobe2    | Sí            | Media        | Variable
# p0f_auto     | Pasivo      | p0f         | Sí            | Baja         | Alta si hay tráfico
#
# Recomendaciones por método:
# - Usa `nmap_A` si necesitas la detección de SO más completa y detallada (aunque sea más ruidoso).
# - Usa `nmap_O` si solo deseas detectar el sistema operativo de forma rápida y precisa, sin escanear servicios.
# - Usa `xprobe2` si `nmap` falla, o deseas probar una técnica basada en ICMP menos convencional.
# - Usa `p0f_auto` si necesitas evitar ser detectado (detección pasiva), ideal en redes sensibles.
#------------------------------------------------------------------------------------------------------------

set -e
shopt -s nocasematch

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

check_cmd() {
  command -v "$1" &>/dev/null || {
    echo -e "${RED}Falta el comando '$1'. Instálalo y vuelve a intentarlo.${NC}"
    exit 1
  }
}

ttl_guess() {
  local tgt="$1"
  ttl=$(ping -c 1 -W 1 "$tgt" 2>/dev/null | grep -oE "ttl=[0-9]+" | cut -d= -f2)
  if [[ -z "$ttl" ]]; then
    echo "Desconocido"
  elif (( ttl >= 128 )); then
    echo "Windows (TTL ≈ $ttl)"
  elif (( ttl >= 64 )); then
    echo "Linux/Unix (TTL ≈ $ttl)"
  else
    echo "Desconocido (TTL ≈ $ttl)"
  fi
}

scan_nmap_O() {
  sudo nmap -O -Pn -n "$1" | grep -m1 "OS details" || true
}

scan_nmap_A() {
  sudo nmap -A -Pn -n "$1" | grep -m1 "OS details" || true
}

scan_xprobe2() {
  sudo xprobe2 -v "$1" 2>/dev/null | grep -m1 "Remote operating system" || true
}

scan_p0f_auto() {
  local tgt="$1"
  local iface="$2"
  local p0f_log="/tmp/p0f_$tgt.log"

  echo -e "${YELLOW}Ejecutando p0f pasivo (15 s) y generando tráfico hacia $tgt...${NC}"
  
  # Ejecutar p0f en segundo plano
  sudo timeout 15 p0f -i "$iface" > "$p0f_log" 2>/dev/null &
  sleep 2  # Aseguramos que p0f ya está escuchando

  # Generar tráfico (ping silencioso)
  ping -c 1 -W 1 "$tgt" >/dev/null 2>&1 || true

  # Esperar a que p0f termine
  wait

  # Extraer resultado
  grep "$tgt" "$p0f_log" | head -n1 || true
}

# ---------------- INICIO ----------------

for c in nmap ping; do check_cmd "$c"; done

read -rp "Ingresa la(s) IP(s) o red/CIDR objetivo (espacio separador): " TARGETS
[[ -z $TARGETS ]] && { echo -e "${RED}No se ingresaron objetivos.${NC}"; exit 1; }

echo -e "${GREEN}\nSelecciona el método de detección de SO:${NC}"
echo "  1) Nmap (-O)"
echo "  2) Nmap completo (-A)"
echo "  3) Xprobe2"
echo "  4) p0f (pasivo con ping automático)"
read -rp "Opción [1-4]: " OPTION

case "$OPTION" in
  1) METHOD="nmap_O"      ; check_cmd sudo ;;
  2) METHOD="nmap_A"      ; check_cmd sudo ;;
  3) METHOD="xprobe2"     ; check_cmd xprobe2 ; check_cmd sudo ;;
  4) METHOD="p0f_auto"    ; check_cmd p0f     ; check_cmd timeout ; check_cmd sudo ;;
  *) echo -e "${RED}Opción inválida.${NC}" ; exit 1 ;;
esac

IFS=' ' read -r -a ARRAY <<< "$TARGETS"
for tgt in "${ARRAY[@]}"; do
  echo -e "${GREEN}\n=== Objetivo: $tgt ===${NC}"

  result=""
  if [[ $METHOD == "p0f_auto" ]]; then
    read -rp "Interfaz para escuchar (ej. eth0 o wlan0): " IFACE
    [[ -z $IFACE ]] && { echo -e "${RED}Interfaz requerida.${NC}" ; continue ; }
    result=$(scan_p0f_auto "$tgt" "$IFACE")
  else
    result=$(scan_"$METHOD" "$tgt")
  fi

  if [[ -n $result ]]; then
    echo -e "${YELLOW}Resultado:${NC} $result"
  else
    echo -e "${YELLOW}Fingerprinting no concluyente. Usando heurística TTL...${NC}"
    echo "Resultado: $(ttl_guess "$tgt")"
  fi
done

echo -e "${GREEN}\nProceso terminado.${NC}"
