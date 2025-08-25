# Monitor de Rede - README

## Descrição
Este é um script Python simples para monitorar dispositivos conectados à sua rede local. Ele detecta IP, MAC, fabricante e tipo aproximado do dispositivo. Todos os registros são salvos em um arquivo de log JSON.

## Requisitos
- Python 3.10+
- Bibliotecas Python:
  - `scapy`
  - `mac-vendor-lookup`
- Não utiliza `netifaces` nem alertas sonoros.

## Instalação (Debian/Ubuntu)
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install python3 python3-venv python3-pip -y
python3 -m venv ~/rede_venv
source ~/rede_venv/bin/activate
pip install scapy mac-vendor-lookup

## Execução
sudo ~/rede_venv/bin/python ~/Documents/Github/MonitorRede/monitor_rede.py
Todos os logs serão salvos em dispositivos_rede.json.

## Observações
O script precisa de sudo para realizar o escaneamento ARP.
Apenas dispositivos ativos na rede serão detectados.
O histórico de dispositivos é mantido no arquivo dispositivos_rede.json.