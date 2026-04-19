import os
import json
import time
import socket
import logging
import threading
import ipaddress
import argparse
import requests
from scapy.all import conf, ARP, Ether, srp, logging as scapy_logging

# --- SILENCIADOR DE AVISOS ---
conf.verb = 0 
scapy_logging.getLogger("scapy.runtime").setLevel(scapy_logging.ERROR)

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from colorama import init, Fore, Style

init(autoreset=True)

# --- CONFIGURAÇÕES ---
VERSION = "3.7.0"
CONFIG_FILE = "config.json"
WHITELIST_FILE = "autorizados.json"
REPORTS_DIR = "relatorios"
MEU_BOT_TOKEN = os.getenv('WATCHDOG_TOKEN')

logging.basicConfig(filename='watchdog.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# --- APOIO TÉCNICO ---

def load_whitelist():
    if not os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE, 'w') as f: json.dump([], f)
        return []
    with open(WHITELIST_FILE, 'r') as f: return json.load(f)

def get_vendor(mac):
    try:
        vendor = conf.manufdb._get_manuf(mac)
        return vendor if vendor else "Desconhecido"
    except: return "Desconhecido"

def port_scan_turbo(ip):
    portas_alvo = [22, 80, 443, 445, 3389]
    open_ports = []
    def check(p):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.15)
                if s.connect_ex((ip, p)) == 0: open_ports.append(str(p))
        except: pass
    threads = [threading.Thread(target=check, args=(p,)) for p in portas_alvo]
    for t in threads: t.start()
    for t in threads: t.join()
    return ", ".join(open_ports) if open_ports else "Nenhuma"

# --- RELATÓRIOS E PDF ---

def gerar_pdf_audit(dispositivos, rede):
    if not os.path.exists(REPORTS_DIR): os.makedirs(REPORTS_DIR)
    path = os.path.join(REPORTS_DIR, f"Audit_{time.strftime('%Y%m%d_%H%M%S')}.pdf")
    
    c = canvas.Canvas(path, pagesize=letter)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, 750, f"RELATÓRIO DE AUDITORIA DE REDE - v{VERSION}")
    c.setFont("Helvetica", 10)
    c.drawString(50, 730, f"Alvo: {rede} | Data: {time.ctime()}")
    c.line(50, 720, 550, 720)
    
    y = 690
    for d in dispositivos:
        if y < 100: c.showPage(); y = 750
        status_color = "(!) " if d['status'] == "SUSPEITO" else ""
        c.setFont("Helvetica-Bold", 10)
        c.drawString(50, y, f"{status_color}IP: {d['ip']} | MAC: {d['mac']} | {d['status']}")
        c.setFont("Helvetica", 9)
        c.drawString(60, y-12, f"Fabricante: {d['vendor']} | Portas Abertas: {d['portas']}")
        y -= 40
        
    c.save()
    return path

# --- CORE ---

def load_config():
    if not os.path.exists(CONFIG_FILE):
        print(Fore.CYAN + "=== GUSTAVO WATCHDOG SETUP ===")
        rede = input("Rede alvo (ex: 192.168.15.0/24): ")
        chat = input("Chat ID Telegram: ")
        c = {"rede": rede, "chat_id": chat, "intervalo_min": 5}
        with open(CONFIG_FILE, 'w') as f: json.dump(c, f, indent=4)
        return c
    with open(CONFIG_FILE, 'r') as f: return json.load(f)

def enviar_telegram(msg, config):
    if not MEU_BOT_TOKEN: return
    url = f"https://api.telegram.org/bot{MEU_BOT_TOKEN}/sendMessage"
    try: requests.post(url, data={"chat_id": config['chat_id'], "text": msg, "parse_mode": "Markdown"}, timeout=5)
    except: pass

def run_scan(config, continuo=False):
    if not MEU_BOT_TOKEN:
        print(Fore.RED + "ERRO: Token (WATCHDOG_TOKEN) não configurado!")
        return

    whitelist = load_whitelist()
    print(f"{Fore.YELLOW}[*] Escaneando {config['rede']}...")
    
    try:
        while True:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=config['rede']), timeout=2, verbose=False)
            resultados = []
            
            print(f"\n{Fore.WHITE}{'STATUS':<12} | {'IP':<15} | {'FABRICANTE'}")
            print("-" * 60)

            for _, r in ans:
                mac, ip = r.hwsrc.lower(), r.psrc
                v = get_vendor(mac)
                p = port_scan_turbo(ip)
                status = "AUTORIZADO" if mac in whitelist else "SUSPEITO"
                
                resultados.append({'ip': ip, 'mac': mac, 'vendor': v, 'portas': p, 'status': status})
                
                cor = Fore.GREEN if status == "AUTORIZADO" else Fore.RED
                print(f"{cor}{status:<12} | {ip:<15} | {v}")

            # Gera PDF e Log
            if resultados:
                pdf_path = gerar_pdf_audit(resultados, config['rede'])
                logging.info(f"Scan finalizado. PDF gerado: {pdf_path}")
                print(Fore.BLUE + f"\n[!] Relatório salvo: {pdf_path}")
                
                suspeitos = sum(1 for r in resultados if r['status'] == "SUSPEITO")
                if suspeitos > 0:
                    enviar_telegram(f"⚠️ *ALERTA:* {suspeitos} desconhecidos na rede!\nRelatório: `{os.path.basename(pdf_path)}`", config)

            if not continuo: break
            print(Fore.YELLOW + f"\n[*] Aguardando {config['intervalo_min']} min para o próximo ciclo...")
            time.sleep(config['intervalo_min'] * 60)
            
    except KeyboardInterrupt: pass

def menu():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scan", action="store_true")
    args = parser.parse_args()
    config = load_config()

    if args.scan:
        run_scan(config, False)
        return

    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print(Fore.BLUE + "═"*60)
        print(f"    GUSTAVO WATCHDOG v{VERSION} | ALVO: {config['rede']}")
        print(Fore.BLUE + "═"*60)
        print(" 1 - Monitoramento Contínuo\n 2 - Snapshot Único + Gerar PDF\n 3 - Alterar Rede Alvo\n 4 - Sair")
        
        op = input("\nEscolha: ")
        if op == "1": run_scan(config, True)
        elif op == "2": run_scan(config, False); input("\nFim. Enter para voltar...")
        elif op == "3": 
            nova = input("Nova rede (ex: 192.168.15.0/24): ")
            if nova: config['rede'] = nova; json.dump(config, open(CONFIG_FILE, 'w'), indent=4)
        elif op == "4": break

if __name__ == "__main__":
    menu()