# Watchdog Network Monitor 🛡️

Monitor de rede em Python que utiliza o protocolo ARP para detecção de novos dispositivos e alertas em tempo real.

## ⚠️ Requisito Obrigatório (Windows)
Para que este script funcione no Windows, é necessário instalar o **Npcap**. Ele permite que a biblioteca Scapy realize o "sniffing" de pacotes na interface de rede.
- Download: [https://npcap.com/#download](https://npcap.com/#download)
- *Nota: Durante a instalação, selecione a opção "Install Npcap in WinPcap API-compatible Mode".*

## 🚀 Funcionalidades
- Varredura de sub-rede via pacotes ARP.
- Identificação de novos dispositivos ativos.
- Alertas automáticos via Telegram (Bot API).
- Geração de relatórios em PDF.

## 🛠️ Tecnologias Utilizadas
- Python 3.12
- Scapy (Monitoramento de rede)
- Telebot (Integração Telegram)
- FPDF (Relatórios em PDF)

## 🔧 Como utilizar
1. Instale as dependências: `pip install -r requirements.txt`
2. Certifique-se de ter o Npcap instalado.
3. Configure seu Token no arquivo `config.json`.
4. Execute o script: `python watchdog.py`