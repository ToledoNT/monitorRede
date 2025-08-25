#!/usr/bin/env python3
import scapy.all as scapy
import socket
import json
import time
import os
from datetime import datetime
import ipaddress
import netifaces
from mac_vendor_lookup import MacLookup
from collections import defaultdict, deque
import threading
import argparse
import logging
import sys
from typing import List, Dict, Set, Tuple, Optional, Any

# ---------------- CONFIGURAÇÃO ---------------- #
LOG_FILE = "dispositivos_rede.json"
INTERVALO = 60  # segundos entre escaneamentos
ALERTAS_VISUAIS = True
HISTORY_SIZE = 100  # Número de entradas a manter em memória
SCAN_TIMEOUT = 2  # Timeout para escaneamento ARP
PORT_SCAN_TIMEOUT = 0.3  # Timeout para escaneamento de portas
MAX_PORT_SCANS = 3  # Número máximo de dispositivos para escanear portas simultaneamente

# ---------------- CONFIGURAÇÃO DE LOGGING ---------------- #
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("network_monitor.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# ---------------- ESTRUTURAS DE DADOS ---------------- #
historico_dispositivos = defaultdict(lambda: deque(maxlen=HISTORY_SIZE))
dispositivos_conhecidos = set()

# ---------------- FUNÇÕES AUXILIARES ---------------- #
def obter_faixa_rede() -> Tuple[Optional[str], Optional[str]]:
    try:
        gateways = netifaces.gateways()
        default_interface = gateways['default'][netifaces.AF_INET][1]
        addrs = netifaces.ifaddresses(default_interface)
        if netifaces.AF_INET in addrs:
            for addr in addrs[netifaces.AF_INET]:
                ip = addr.get('addr')
                netmask = addr.get('netmask')
                if ip and not ip.startswith("127.") and netmask:
                    try:
                        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                        return str(network), default_interface
                    except Exception as e:
                        logger.error(f"Erro ao calcular rede: {e}")
                        continue
    except Exception as e:
        logger.error(f"Erro ao obter interface padrão: {e}")
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    ip = addr.get('addr')
                    netmask = addr.get('netmask')
                    if ip and not ip.startswith("127.") and netmask:
                        try:
                            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                            return str(network), iface
                        except Exception as e:
                            logger.error(f"Erro ao calcular rede: {e}")
                            continue
    return None, None

def identificar_dispositivo(mac: str) -> Tuple[str, str]:
    try:
        fabricante = MacLookup().lookup(mac)
    except Exception:
        fabricante = "Desconhecido"

    if not hasattr(identificar_dispositivo, 'cache'):
        identificar_dispositivo.cache = {}
    if mac in identificar_dispositivo.cache:
        return identificar_dispositivo.cache[mac]

    fabricante_lower = fabricante.lower()
    tipo = "Desconhecido"

    fabricante_to_type = {
        "apple": "Dispositivo Apple",
        "samsung": "Dispositivo Samsung",
        "huawei": "Dispositivo Huawei",
        "intel": "Computador",
        "dell": "Computador",
        "hp": "Computador",
        "lenovo": "Computador",
        "asus": "Computador",
        "acer": "Computador",
        "xiaomi": "Dispositivo Xiaomi",
        "redmi": "Dispositivo Xiaomi",
        "poco": "Dispositivo Xiaomi",
        "tp-link": "Dispositivo de Rede",
        "d-link": "Dispositivo de Rede",
        "netgear": "Dispositivo de Rede",
        "linksys": "Dispositivo de Rede",
        "google": "Dispositivo Google",
        "nest": "Dispositivo Google",
        "amazon": "Dispositivo Amazon",
        "echo": "Dispositivo Amazon",
        "kindle": "Dispositivo Amazon",
        "raspberry": "Raspberry Pi",
        "router": "Roteador/Modem",
        "gateway": "Roteador/Modem",
        "modem": "Roteador/Modem",
        "phone": "Smartphone",
        "mobile": "Smartphone",
        "smartphone": "Smartphone",
        "tv": "Smart TV",
        "television": "Smart TV",
        "iot": "Dispositivo IoT",
        "embedded": "Dispositivo IoT"
    }

    for key, value in fabricante_to_type.items():
        if key in fabricante_lower:
            tipo = value
            break

    resultado = (fabricante, tipo)
    identificar_dispositivo.cache[mac] = resultado
    return resultado

def escanear_portas(ip: str, portas: List[int] = None) -> Dict[str, List[Any]]:
    if portas is None:
        portas = [21, 22, 23, 25, 53, 80, 443, 3389, 8080, 8443]

    info = {"portas_abertas": [], "servicos": []}
    for porta in portas:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(PORT_SCAN_TIMEOUT)
                if sock.connect_ex((ip, porta)) == 0:
                    info["portas_abertas"].append(porta)
                    try:
                        servico = socket.getservbyport(porta)
                        info["servicos"].append(servico)
                    except OSError:
                        info["servicos"].append("desconhecido")
        except Exception as e:
            logger.debug(f"Erro ao escanear porta {porta} em {ip}: {e}")
    return info

def tocar_alerta() -> None:
    """Função desativada (alerta sonoro removido)."""
    pass

def mostrar_alerta_visual(msg: str) -> None:
    if ALERTAS_VISUAIS:
        print(f"\n\033[91m⚠️  ALERTA: {msg}\033[0m\n")

# ---------------- FUNÇÃO DE ESCANEAMENTO ---------------- #
def escanear_rede(ip_range: str, iface: str) -> List[Dict[str, Any]]:
    dispositivos = []
    try:
        arp_request = scapy.ARP(pdst=ip_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        pacote = broadcast / arp_request
        resposta, _ = scapy.srp(pacote, iface=iface, timeout=SCAN_TIMEOUT, verbose=False)

        if not resposta:
            logger.warning("Nenhuma resposta ARP recebida. Verifique permissões e rede.")
            return dispositivos

        logger.info(f"{len(resposta)} dispositivo(s) respondendo na rede.")
        dispositivos_para_escanear = min(MAX_PORT_SCANS, len(resposta))

        for i, (sent, received) in enumerate(resposta):
            try:
                host = socket.gethostbyaddr(received.psrc)[0]
            except (socket.herror, socket.gaierror):
                host = received.psrc

            fabricante, tipo = identificar_dispositivo(received.hwsrc)
            info_detalhada = {"portas_abertas": [], "servicos": []}
            if i < dispositivos_para_escanear:
                info_detalhada = escanear_portas(received.psrc)

            dispositivo = {
                "ip": received.psrc,
                "mac": received.hwsrc,
                "host": host,
                "fabricante": fabricante,
                "tipo": tipo,
                "portas_abertas": info_detalhada["portas_abertas"],
                "servicos": info_detalhada["servicos"],
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "ultima_visto": datetime.now().isoformat()
            }
            dispositivos.append(dispositivo)
            historico_dispositivos[received.hwsrc].append(dispositivo)
    except PermissionError:
        logger.error("Permissão negada. Execute o script com sudo/administrador.")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Erro ao escanear a rede: {e}")
    return dispositivos

# ---------------- FUNÇÃO DE LOG ---------------- #
def salvar_log(dispositivos: List[Dict[str, Any]]) -> None:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = {"timestamp": ts, "dispositivos": dispositivos}

    try:
        logs_existentes = []
        if os.path.exists(LOG_FILE):
            try:
                with open(LOG_FILE, "r") as f:
                    for linha in f:
                        if linha.strip():
                            logs_existentes.append(json.loads(linha.strip()))
            except json.JSONDecodeError:
                logger.warning("Arquivo de log corrompido. Criando novo.")

        logs_existentes = logs_existentes[-1000:]
        logs_existentes.append(log_entry)

        with open(LOG_FILE, "w") as f:
            for entrada in logs_existentes:
                f.write(json.dumps(entrada) + "\n")
    except Exception as e:
        logger.error(f"Erro ao salvar log: {e}")

def carregar_historico() -> Set[str]:
    conhecidos = set()
    try:
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "r") as f:
                for linha in f:
                    if linha.strip():
                        entrada = json.loads(linha.strip())
                        for disp in entrada.get("dispositivos", []):
                            conhecidos.add(disp["mac"])
    except Exception as e:
        logger.error(f"Erro ao carregar histórico: {e}")
    return conhecidos

# ---------------- DASHBOARD ---------------- #
def exibir_dashboard(dispositivos: List[Dict[str, Any]], novos_dispositivos: Set[str] = None) -> None:
    if novos_dispositivos is None:
        novos_dispositivos = set()

    os.system('cls' if os.name == 'nt' else 'clear')
    print("="*80)
    print("MONITOR DE REDE - DASHBOARD".center(80))
    print("="*80)
    print(f"Tempo: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Dispositivos encontrados: {len(dispositivos)}")
    print(f"Novos dispositivos: {len(novos_dispositivos)}")
    print("="*80)

    if novos_dispositivos:
        print("\n\033[93m⚠️  NOVOS DISPOSITIVOS DETECTADOS:\033[0m")
        for disp in dispositivos:
            if disp["mac"] in novos_dispositivos:
                print(f"  \033[91m• {disp['ip']} - {disp['mac']} - {disp['fabricante']} - {disp['tipo']}\033[0m")

    print("\n\033[92mDISPOSITIVOS NA REDE:\033[0m")
    for i, disp in enumerate(dispositivos, 1):
        status = " \033[91m(NOVO)\033[0m" if disp["mac"] in novos_dispositivos else ""
        print(f"  {i}. {disp['ip']} - {disp['host']} - {disp['fabricante']} - {disp['tipo']}{status}")
        if disp["portas_abertas"]:
            print(f"     Portas abertas: {disp['portas_abertas']} ({', '.join(disp['servicos'])})")
    print("="*80)
    print("Pressione Ctrl+C para sair")
    print("="*80)

# ---------------- ARGUMENTOS DE LINHA DE COMANDO ---------------- #
def parse_arguments():
    parser = argparse.ArgumentParser(description='Monitor de rede para detectar dispositivos conectados')
    parser.add_argument('--interval', '-i', type=int, default=INTERVALO, 
                        help=f'Intervalo entre escaneamentos em segundos (padrão: {INTERVALO})')
    parser.add_argument('--log', '-l', type=str, default=LOG_FILE,
                        help=f'Arquivo de log (padrão: {LOG_FILE})')
    parser.add_argument('--no-visual', action='store_true', 
                        help='Desativar alertas visuais')
    parser.add_argument('--network', '-n', type=str,
                        help='Faixa de rede específica para escanear (ex: 192.168.1.0/24)')
    parser.add_argument('--interface', '-I', type=str,
                        help='Interface de rede específica para usar')
    return parser.parse_args()

# ---------------- LOOP PRINCIPAL ---------------- #
def main():
    args = parse_arguments()
    global ALERTAS_VISUAIS, LOG_FILE, INTERVALO
    if args.no_visual:
        ALERTAS_VISUAIS = False
    LOG_FILE = args.log
    INTERVALO = args.interval

    if args.network and args.interface:
        ip_rede, iface = args.network, args.interface
    else:
        ip_rede, iface = obter_faixa_rede()

    if not ip_rede or not iface:
        logger.error("Não foi possível detectar a rede ativa.")
        sys.exit(1)

    conhecidos = carregar_historico()
    logger.info(f"Monitor iniciado na interface {iface}. Escaneando {ip_rede} a cada {INTERVALO}s...")
    logger.info(f"Dispositivos conhecidos: {len(conhecidos)}")

    try:
        while True:
            start_time = time.time()
            dispositivos = escanear_rede(ip_rede, iface)
            atuais = set(d["mac"] for d in dispositivos)
            novos = atuais - conhecidos

            if novos:
                for disp in dispositivos:
                    if disp["mac"] in novos:
                        msg = f"Novo dispositivo: {disp['ip']} ({disp['mac']}) - {disp['fabricante']} - {disp['tipo']}"
                        mostrar_alerta_visual(msg)
                        logger.warning(msg)
                salvar_log(dispositivos)
                conhecidos = atuais

            exibir_dashboard(dispositivos, novos)
            elapsed = time.time() - start_time
            if elapsed < INTERVALO:
                time.sleep(INTERVALO - elapsed)
    except KeyboardInterrupt:
        print("\nMonitor encerrado. Log salvo em", LOG_FILE)
        logger.info("Monitor encerrado pelo usuário")

if __name__ == "__main__":
    main()