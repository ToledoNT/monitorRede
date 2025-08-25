# Monitor de Rede - README

## 📌 Descrição
Script em **Python** para monitorar dispositivos conectados à sua rede local.  
Ele detecta **IP, MAC, fabricante** e o **tipo aproximado** do dispositivo.  
Todos os registros são salvos em um arquivo **JSON** para histórico.

---

## ⚙️ Requisitos
- Python **3.10+**
- Bibliotecas Python:
  - `scapy`
  - `mac-vendor-lookup`

---

## 🖥️ Instalação (Debian/Ubuntu)
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install python3 python3-venv python3-pip -y

# Criar ambiente virtual
python3 -m venv ~/rede_venv
source ~/rede_venv/bin/activate

# Instalar dependências
pip install scapy mac-vendor-lookup

🚀 Execução

sudo ~/rede_venv/bin/python ~/Documents/Github/MonitorRede/monitor_rede.py

📂 Logs

    Todos os dispositivos detectados serão salvos em:

    dispositivos_rede.json

    O histórico não é sobrescrito, sempre atualizado.

🔎 Observações

    O script precisa de sudo para realizar o escaneamento ARP.

    Apenas dispositivos ativos na rede serão detectados.

    O arquivo dispositivos_rede.json mantém o histórico de conexões.