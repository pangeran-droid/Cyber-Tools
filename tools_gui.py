#!/usr/bin/env python3
"""
tools_gui.py
Safe / educational GUI with features:
 - Splash screen
 - Modern look using ttkbootstrap (fallback to tkinter)
 - 30 feature buttons (dummy/safe implementations) arranged in three columns
 - Graceful handling when optional dependencies are missing

Instructions:
 - (optional) Place icon.png in same folder to show an app icon.
 - Optional dependencies (for full functionality):
     pip install requests beautifulsoup4 ttkbootstrap pyautogui
 - Run: python tools_gui.py

"""

import os
import socket
import random
import string
import time
import json
from pathlib import Path
import tkinter as tk
from tkinter import simpledialog, messagebox, scrolledtext, PhotoImage

HAS_REQUESTS = True
HAS_BS4 = True
HAS_TTB = True
HAS_PYAUTOGUI = True

try:
    import requests
except Exception:
    HAS_REQUESTS = False

try:
    from bs4 import BeautifulSoup
except Exception:
    HAS_BS4 = False

try:
    import ttkbootstrap as ttk
except Exception:
    HAS_TTB = False

try:
    import pyautogui
except Exception:
    HAS_PYAUTOGUI = False

APP_DIR = Path(__file__).parent
ICON_PNG = APP_DIR / "assets/icon.png"

def popup_text(title, text, width=70, height=25):
    win = tk.Toplevel()
    win.title(title)
    txt = scrolledtext.ScrolledText(win, wrap=tk.WORD, width=width, height=height)
    txt.insert(tk.END, text)
    txt.config(state=tk.DISABLED)
    txt.pack(padx=10, pady=10)
    win.update_idletasks()
    w = win.winfo_width(); h = win.winfo_height()
    x = (win.winfo_screenwidth() // 2) - (w // 2)
    y = (win.winfo_screenheight() // 2) - (h // 2)
    win.geometry(f"+{x}+{y}")


def keylogger_safe(parent=None):
    """
    SAFE keylogger: only records text typed into the provided textarea.
    There is a clear Start / Stop and Save button. Does NOT capture global keystrokes.
    """
    win = tk.Toplevel()
    win.title("Keylogger (SAFE) - Educational")
    win.geometry("600x420")

    tk.Label(win, text="Keylogger (SAFE) — hanya merekam teks yang diketik di sini.",
             font=("Segoe UI", 10)).pack(pady=(8,4))

    instr = ("Instruksi:\n"
             "- Ketik di area di bawah, lalu tekan 'Save Log'.\n"
             "- Ini hanya contoh edukasi: aplikasi TIDAK merekam tombol di luar jendela ini.")
    tk.Label(win, text=instr, font=("Segoe UI", 9), justify=tk.LEFT).pack(padx=10, anchor="w")

    txt = scrolledtext.ScrolledText(win, wrap=tk.WORD, width=70, height=14)
    txt.pack(padx=10, pady=8)

    out_file = APP_DIR / "keylog_safe.txt"

    def save_log():
        content = txt.get("1.0", tk.END).rstrip()
        if not content:
            messagebox.showwarning("Kosong", "Tidak ada teks untuk disimpan.")
            return
        with open(out_file, "a", encoding="utf-8") as f:
            f.write(f"--- Log {time.ctime()} ---\n")
            f.write(content + "\n\n")
        messagebox.showinfo("Saved", f"Log disimpan ke: {out_file}")

    def clear_text():
        if messagebox.askyesno("Konfirmasi", "Hapus area teks?"):
            txt.delete("1.0", tk.END)

    btn_frame = tk.Frame(win)
    btn_frame.pack(pady=(4,10))
    tk.Button(btn_frame, text="Save Log", command=save_log, width=12).pack(side=tk.LEFT, padx=6)
    tk.Button(btn_frame, text="Clear", command=clear_text, width=12).pack(side=tk.LEFT, padx=6)
    tk.Button(btn_frame, text="Close", command=win.destroy, width=12).pack(side=tk.LEFT, padx=6)


def port_scanner(parent=None):
    target = simpledialog.askstring("Port Scanner", "Masukkan IP atau Host:")
    if not target:
        return
    ports = [21,22,23,25,53,80,110,139,143,443,445,3389,8080]
    results = []
    for p in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.8)
            res = sock.connect_ex((target, p))
            if res == 0:
                results.append(f"Port {p} -> TERBUKA")
            sock.close()
        except Exception as e:
            results.append(f"Port {p} -> ERROR ({e})")
    popup_text(f"Hasil Scan: {target}", "\n".join(results))

def password_generator(parent=None):
    try:
        length = int(simpledialog.askstring("Password Generator", "Panjang password (mis: 16):") or "12")
    except Exception:
        messagebox.showwarning("Input salah", "Masukkan angka untuk panjang password.")
        return
    pool = string.ascii_letters + string.digits + string.punctuation
    pwd = "".join(random.choice(pool) for _ in range(length))
    messagebox.showinfo("Password Generated", pwd)

def brute_force_dummy(parent=None):
    username = "admin"
    correct = "1234"
    out = [f"[Dummy] Target: {username}"]
    for i in range(10000):
        guess = str(i).zfill(4)
        if guess == correct:
            out.append(f"Password ditemukan: {guess} (SIMULASI)")
            break
    popup_text("Brute Force (Dummy)", "\n".join(out))

def caesar_cipher(parent=None):
    mode = simpledialog.askstring("Caesar Cipher", "Mode: Encrypt (E) / Decrypt (D)") or "E"
    mode = mode.strip().upper()
    text = simpledialog.askstring("Caesar Cipher", "Masukkan teks:") or ""
    try:
        shift = int(simpledialog.askstring("Caesar Cipher", "Shift (angka):") or "0")
    except Exception:
        messagebox.showwarning("Input salah", "Shift harus angka.")
        return
    res = []
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            if mode == 'E':
                res.append(chr((ord(ch)-base + shift) % 26 + base))
            else:
                res.append(chr((ord(ch)-base - shift) % 26 + base))
        else:
            res.append(ch)
    popup_text("Hasil Caesar Cipher", "".join(res))

def website_crawler(parent=None):
    if not HAS_REQUESTS or not HAS_BS4:
        messagebox.showerror("Missing dependency",
            "Feature ini membutuhkan paket 'requests' dan 'beautifulsoup4'.\nInstall: pip install requests beautifulsoup4")
        return
    url = simpledialog.askstring("Website Crawler", "Masukkan URL (sertakan http/https):")
    if not url:
        return
    try:
        r = requests.get(url, timeout=10)
        soup = BeautifulSoup(r.text, "html.parser")
        links = [a.get('href') for a in soup.find_all('a', href=True)]
        popup_text("Hasil Crawler", "\n".join(links) if links else "Tidak ada link ditemukan.")
    except Exception as e:
        messagebox.showerror("Error", f"Gagal mengambil halaman: {e}")

def mac_changer_sim(parent=None):
    """
    SIMULATION-only MAC changer UI.
    Shows:
      - Random MAC generator
      - The OS-specific commands you (the user) must run AS ADMIN to change MAC.
    The function does NOT execute commands.
    """
    win = tk.Toplevel()
    win.title("MAC Changer (SIMULATION)")
    win.geometry("560x380")

    tk.Label(win, text="MAC Changer — SIMULATION (tidak mengeksekusi perubahan).",
             font=("Segoe UI", 10)).pack(pady=(8,4))
    tk.Label(win, text="Pilih atau buat MAC baru, lalu ikuti perintah yang ditampilkan (JALANKAN SENDIRI SEBAGAI ADMIN).",
             font=("Segoe UI", 9), justify=tk.LEFT).pack(padx=10, anchor="w")

    frame = tk.Frame(win)
    frame.pack(pady=8, padx=10, fill="x")

    tk.Label(frame, text="MAC baru (manual):").grid(row=0, column=0, sticky="w")
    entry_mac = tk.Entry(frame, width=30)
    entry_mac.grid(row=0, column=1, padx=6, pady=6)

    def gen_random_mac():
        # locally administered address (set second-least-significant bit of first octet)
        import random
        first = random.randint(0x00, 0xff)
        first = (first & 0xfe) | 0x02
        mac = [first] + [random.randint(0x00, 0xff) for _ in range(5)]
        mac_str = ":".join(f"{b:02x}" for b in mac)
        entry_mac.delete(0, tk.END)
        entry_mac.insert(0, mac_str)

    tk.Button(frame, text="Generate Random MAC", command=gen_random_mac, width=20).grid(row=1, column=0, pady=6)
    tk.Button(frame, text="Copy Command (Show)", command=lambda: show_mac_commands(entry_mac.get()), width=20).grid(row=1, column=1, pady=6)

    cmd_area = scrolledtext.ScrolledText(win, height=10, wrap=tk.WORD)
    cmd_area.pack(padx=10, pady=8, fill="both", expand=True)

    def show_mac_commands(mac_value):
        mac_value = mac_value.strip()
        if not mac_value:
            messagebox.showwarning("MAC kosong", "Isi MAC dulu (atau Generate Random).")
            return

        cmds = []
        cmds.append(f"# Perintah yang harus dijalankan SEBAGAI ADMIN / ROOT. Aplikasi ini TIDAK mengeksekusi perintah.")
        cmds.append("\n--- Linux (contoh, ganti iface dengan antarmuka Anda) ---")
        cmds.append(f"sudo ip link set dev <iface> down")
        cmds.append(f"sudo ip link set dev <iface> address {mac_value}")
        cmds.append(f"sudo ip link set dev <iface> up")
        cmds.append("\n--- macOS (contoh, ganti en0 dengan antarmuka Anda) ---")
        cmds.append(f"sudo ifconfig en0 ether {mac_value}")
        cmds.append("\n--- Windows (PowerShell) ---")
        cmds.append("# Windows membutuhkan dukungan driver vendor; pendekatan umum adalah melalui registry atau alat vendor.")
        cmds.append("Get-NetAdapter | Format-Table -AutoSize")
        cmds.append("# Kemudian gunakan utilitas vendor atau ubah registry 'NetworkAddress' untuk adaptor, lalu restart adaptor.")
        cmd_area.delete("1.0", tk.END)
        cmd_area.insert(tk.END, "\n".join(cmds))
        cmd_area.see(tk.END)

def ping_tester(parent=None):
    host = simpledialog.askstring("Ping Tester", "Masukkan host atau IP:")
    if not host:
        return
    cmd = f"ping -c 4 {host}" if os.name != 'nt' else f"ping {host}"
    try:
        out = os.popen(cmd).read()
        popup_text("Ping Result", out)
    except Exception as e:
        messagebox.showerror("Error", str(e))

def ip_locator(parent=None):
    if not HAS_REQUESTS:
        messagebox.showerror("Missing dependency", "Feature ini membutuhkan paket 'requests'.\nInstall: pip install requests")
        return
    ip = simpledialog.askstring("IP Locator", "Masukkan IP (kosong = auto detect):") or ""
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=8).json()
        lines = [f"{k}: {v}" for k, v in r.items()]
        popup_text("IP Lookup", "\n".join(lines))
    except Exception as e:
        messagebox.showerror("Error", f"Gagal: {e}")

def screenshot_taker(parent=None):
    if not HAS_PYAUTOGUI:
        messagebox.showerror("Missing dependency", "Feature ini membutuhkan 'pyautogui'.\nInstall: pip install pyautogui")
        return
    fname = simpledialog.askstring("Screenshot", "Nama file (mis: shot.png):") or "screenshot.png"
    try:
        img = pyautogui.screenshot()
        img.save(fname)
        messagebox.showinfo("Screenshot", f"Tersimpan: {fname}")
    except Exception as e:
        messagebox.showerror("Error", f"Gagal: {e}")

def packet_sniffer_sim(parent=None):
    win = tk.Toplevel()
    win.title("11. Packet Sniffer (Simulasi)")
    win.geometry("600x400")
    
    tk.Label(win, text="Simulasi Packet Sniffer (output acak)", font=("Segoe UI", 10)).pack(pady=5)
    
    output_text = scrolledtext.ScrolledText(win, wrap=tk.WORD, width=70, height=15)
    output_text.pack(padx=10, pady=5)
    
    def generate_packets():
        output_text.delete("1.0", tk.END)
        packets = []
        for _ in range(random.randint(5, 15)):
            src_ip = ".".join(map(str, (random.randint(1,254) for _ in range(4))))
            dst_ip = ".".join(map(str, (random.randint(1,254) for _ in range(4))))
            src_port = random.randint(1024, 65535)
            dst_port = random.randint(1, 65535)
            protocol = random.choice(["TCP", "UDP", "ICMP"])
            data_size = random.randint(50, 1500)
            packet_type = random.choice(["HTTP", "DNS", "FTP", "SSH", "TLS"])
            
            packets.append(f"[Waktu: {time.strftime('%H:%M:%S')}] {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Proto: {protocol} | Ukuran: {data_size} byte | Tipe: {packet_type}")
        
        output_text.insert(tk.END, "\n".join(packets))
        output_text.see(tk.END)
        
    tk.Button(win, text="Mulai Sniff (Simulasi)", command=generate_packets, width=20).pack(pady=5)
    tk.Button(win, text="Tutup", command=win.destroy, width=10).pack(pady=5)

def arp_spoofer_sim(parent=None):
    win = tk.Toplevel()
    win.title("12. ARP Spoofer (Simulasi)")
    win.geometry("500x350")
    
    tk.Label(win, text="Simulasi Perubahan Cache ARP", font=("Segoe UI", 10)).pack(pady=5)
    
    output_text = scrolledtext.ScrolledText(win, wrap=tk.WORD, width=60, height=10)
    output_text.pack(padx=10, pady=5)
    
    def simulate_spoof():
        output_text.delete("1.0", tk.END)
        original_arp = [
            "192.168.1.1       00:1A:2B:3C:4D:5E",
            "192.168.1.100     AA:BB:CC:DD:EE:FF",
            "192.168.1.254     01:23:45:67:89:AB"
        ]
        spoofed_mac = "F0:E1:D2:C3:B4:A5"
        
        output_text.insert(tk.END, "--- Cache ARP Awal (Simulasi) ---\n")
        output_text.insert(tk.END, "\n".join(original_arp) + "\n\n")
        
        output_text.insert(tk.END, "--- Memicu Spoof ARP (Simulasi) ---\n")
        output_text.insert(tk.END, f"Attacker mengirim paket ARP palsu, mengklaim bahwa IP 192.168.1.1 memiliki MAC {spoofed_mac}.\n\n")
        
        output_text.insert(tk.END, "--- Cache ARP Setelah Spoof (Simulasi) ---\n")
        spoofed_arp = [
            f"192.168.1.1       {spoofed_mac} (TERUBAH)",
            "192.168.1.100     AA:BB:CC:DD:EE:FF",
            "192.168.1.254     01:23:45:67:89:AB"
        ]
        output_text.insert(tk.END, "\n".join(spoofed_arp))
        output_text.see(tk.END)
        
    tk.Button(win, text="Simulasikan Spoof ARP", command=simulate_spoof, width=20).pack(pady=5)
    tk.Button(win, text="Tutup", command=win.destroy, width=10).pack(pady=5)

def subdomain_finder_sim(parent=None):
    win = tk.Toplevel()
    win.title("13. Subdomain Finder (Simulasi)")
    win.geometry("600x400")

    tk.Label(win, text="Simulasi Pencarian Subdomain", font=("Segoe UI", 10)).pack(pady=5)
    
    domain_entry = tk.Entry(win, width=40)
    domain_entry.insert(0, "example.com")
    domain_entry.pack(pady=5)
    
    output_text = scrolledtext.ScrolledText(win, wrap=tk.WORD, width=70, height=12)
    output_text.pack(padx=10, pady=5)
    
    def find_subdomains_sim():
        domain = domain_entry.get().strip()
        if not domain:
            messagebox.showwarning("Input Kosong", "Masukkan nama domain.")
            return

        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, f"Mencari subdomain untuk {domain}...\n\n")
        
        common_subdomains = ["www", "mail", "ftp", "blog", "dev", "test", "api", "admin", "secure"]
        found_subdomains = []
        
        for sub in common_subdomains:
            full_domain = f"{sub}.{domain}"
            if random.random() > 0.4:
                found_subdomains.append(f"  [Ditemukan]: {full_domain}")
            else:
                found_subdomains.append(f"  [Tidak Ditemukan]: {full_domain}")
        
        output_text.insert(tk.END, "\n".join(found_subdomains))
        output_text.see(tk.END)
        
    tk.Button(win, text="Cari Subdomain (Simulasi)", command=find_subdomains_sim, width=25).pack(pady=5)
    tk.Button(win, text="Tutup", command=win.destroy, width=10).pack(pady=5)

def sql_injection_simulator(parent=None):
    win = tk.Toplevel()
    win.title("14. SQL Injection Simulator (Simulasi)")
    win.geometry("550x450")

    tk.Label(win, text="Simulasi Login Rentan SQL Injection", font=("Segoe UI", 10)).pack(pady=5)

    tk.Label(win, text="Username (Masukkan 'admin' atau 'admin'--):").pack(pady=(10,0))
    username_entry = tk.Entry(win, width=40)
    username_entry.pack(pady=2)
    username_entry.insert(0, "admin")

    tk.Label(win, text="Password (Masukkan 'password' atau 'OR 1=1--'):").pack(pady=(10,0))
    password_entry = tk.Entry(win, width=40, show="*")
    password_entry.pack(pady=2)
    password_entry.insert(0, "password")

    output_label = tk.Label(win, text="", wraplength=400, justify=tk.LEFT)
    output_label.pack(pady=10)

    def simulate_login():
        user = username_entry.get()
        pwd = password_entry.get()
        
        # Simulate backend SQL query
        simulated_query = f"SELECT * FROM users WHERE username = '{user}' AND password = '{pwd}';"
        
        if user == "admin" and pwd == "password":
            output_label.config(text=f"Query Simulasi:\n{simulated_query}\n\n[SIMULASI] Login Berhasil! Selamat datang, admin.")
        elif user == "admin" and pwd == "OR 1=1--":
            output_label.config(text=f"Query Simulasi:\nSELECT * FROM users WHERE username = 'admin' AND password = '' OR 1=1--;\n\n[SIMULASI] SQL Injection Berhasil! Login tanpa password! Selamat datang, admin.")
        elif user == "admin' OR '1'='1" and pwd == "--":
             output_label.config(text=f"Query Simulasi:\nSELECT * FROM users WHERE username = 'admin' OR '1'='1' AND password = '--';\n\n[SIMULASI] SQL Injection Berhasil! Login tanpa password! Selamat datang, admin.")
        else:
            output_label.config(text=f"Query Simulasi:\n{simulated_query}\n\n[SIMULASI] Login Gagal. Username atau password salah.")
            
    tk.Button(win, text="Simulasikan Login", command=simulate_login, width=20).pack(pady=10)
    tk.Button(win, text="Tutup", command=win.destroy, width=10).pack(pady=5)

def dns_spoofer_sim(parent=None):
    win = tk.Toplevel()
    win.title("15. DNS Spoofer (Simulasi)")
    win.geometry("500x350")
    
    tk.Label(win, text="Simulasi Pembajakan DNS", font=("Segoe UI", 10)).pack(pady=5)
    
    tk.Label(win, text="Domain Asli (Contoh: google.com):").pack(pady=(10,0))
    domain_entry = tk.Entry(win, width=40)
    domain_entry.insert(0, "google.com")
    domain_entry.pack(pady=2)
    
    tk.Label(win, text="IP Palsu (Contoh: 1.2.3.4):").pack(pady=(10,0))
    ip_entry = tk.Entry(win, width=40)
    ip_entry.insert(0, "1.2.3.4")
    ip_entry.pack(pady=2)
    
    output_label = tk.Label(win, text="", wraplength=400, justify=tk.LEFT)
    output_label.pack(pady=10)
    
    def simulate_dns_spoof():
        domain = domain_entry.get().strip()
        fake_ip = ip_entry.get().strip()
        
        if not domain or not fake_ip:
            messagebox.showwarning("Input Kosong", "Masukkan domain dan IP palsu.")
            return
            
        original_ip = socket.gethostbyname(domain) if not " " in domain else "Tidak dapat me-resolv"
        
        output_label.config(text=
            f"--- Simulasi Proses DNS ---\n"
            f"Klien mencoba me-resolv '{domain}'.\n"
            f"  [Asli]: {domain} -> {original_ip}\n\n"
            f"--- Setelah Pembajakan DNS (Simulasi) ---\n"
            f"Server DNS palsu merespons:\n"
            f"  [Palsu]: {domain} -> {fake_ip}\n\n"
            f"Klien sekarang akan diarahkan ke IP palsu ini untuk {domain}."
        )
        
    tk.Button(win, text="Simulasikan DNS Spoof", command=simulate_dns_spoof, width=20).pack(pady=10)
    tk.Button(win, text="Tutup", command=win.destroy, width=10).pack(pady=5)

def steganography_tool_sim(parent=None):
    win = tk.Toplevel()
    win.title("16. Steganography Tool (Simulasi)")
    win.geometry("600x450")

    tk.Label(win, text="Simulasi Penyembunyian/Ekstraksi Pesan", font=("Segoe UI", 10)).pack(pady=5)
    
    tk.Label(win, text="Pesan untuk disembunyikan:").pack(pady=(10,0))
    message_entry = tk.Entry(win, width=50)
    message_entry.pack(pady=2)
    message_entry.insert(0, "Pesan rahasia!")

    tk.Label(win, text="Data Gambar Simulasi (string representasi gambar):").pack(pady=(10,0))
    image_data_entry = tk.Entry(win, width=50)
    image_data_entry.pack(pady=2)
    image_data_entry.insert(0, "Ini adalah data gambar dummy 12345.")
    
    output_text = scrolledtext.ScrolledText(win, wrap=tk.WORD, width=70, height=8)
    output_text.pack(padx=10, pady=10)

    def embed_message_sim():
        message = message_entry.get()
        image_data = image_data_entry.get()
        
        if not message or not image_data:
            messagebox.showwarning("Input Kosong", "Masukkan pesan dan data gambar simulasi.")
            return

        simulated_embedded_data = image_data + " [EMBEDDED: " + message + "]"
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, "--- Simulasi Penyembunyian Pesan ---\n")
        output_text.insert(tk.END, f"Pesan '{message}' disembunyikan dalam data gambar simulasi.\n")
        output_text.insert(tk.END, f"Data Gambar dengan Pesan (Simulasi):\n{simulated_embedded_data}")
        output_text.see(tk.END)

    def extract_message_sim():
        simulated_data = output_text.get("1.0", tk.END).strip()
        
        if "[EMBEDDED: " in simulated_data:
            start_index = simulated_data.find("[EMBEDDED: ") + len("[EMBEDDED: ")
            end_index = simulated_data.find("]", start_index)
            extracted_message = simulated_data[start_index:end_index]
            output_text.insert(tk.END, "\n\n--- Simulasi Ekstraksi Pesan ---\n")
            output_text.insert(tk.END, f"Pesan yang diekstrak: '{extracted_message}'")
        else:
            output_text.insert(tk.END, "\n\n--- Simulasi Ekstraksi Pesan ---\n")
            output_text.insert(tk.END, "Tidak ada pesan tersembunyi yang ditemukan dalam data simulasi.")
        output_text.see(tk.END)

    btn_frame = tk.Frame(win)
    btn_frame.pack(pady=5)
    tk.Button(btn_frame, text="Sembunyikan Pesan (Simulasi)", command=embed_message_sim, width=25).pack(side=tk.LEFT, padx=5)
    tk.Button(btn_frame, text="Ekstrak Pesan (Simulasi)", command=extract_message_sim, width=25).pack(side=tk.LEFT, padx=5)
    tk.Button(win, text="Tutup", command=win.destroy, width=10).pack(pady=5)


def network_scanner_sim(parent=None):
    win = tk.Toplevel()
    win.title("17. Network Scanner (Simulasi)")
    win.geometry("600x400")
    
    tk.Label(win, text="Simulasi Pemindaian Jaringan Lokal", font=("Segoe UI", 10)).pack(pady=5)
    
    output_text = scrolledtext.ScrolledText(win, wrap=tk.WORD, width=70, height=15)
    output_text.pack(padx=10, pady=5)
    
    def scan_network_sim():
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, "Memindai perangkat di jaringan lokal (simulasi)...\n\n")
        
        devices = []
        base_ip = "192.168.1."
        
        for i in range(1, 10):
            ip = f"{base_ip}{i}"
            hostname = f"host-{i}.local" if random.random() > 0.3 else "N/A"
            status = random.choice(["Online", "Offline"])
            open_ports = ", ".join(random.sample(["80", "443", "22", "21", "3389"], k=random.randint(0,2)))
            
            devices.append(f"IP: {ip}\n  Hostname: {hostname}\n  Status: {status}\n  Port Terbuka (Simulasi): {open_ports}\n")
        
        output_text.insert(tk.END, "\n".join(devices))
        output_text.see(tk.END)
        
    tk.Button(win, text="Mulai Pindai Jaringan (Simulasi)", command=scan_network_sim, width=25).pack(pady=5)
    tk.Button(win, text="Tutup", command=win.destroy, width=10).pack(pady=5)

def email_bomber_sim(parent=None):
    win = tk.Toplevel()
    win.title("18. Email Bomber (Simulasi)")
    win.geometry("500x350")
    
    tk.Label(win, text="Simulasi Pengiriman Email Massal", font=("Segoe UI", 10)).pack(pady=5)
    tk.Label(win, text="(Tidak ada email yang benar-benar dikirim)", font=("Segoe UI", 8, "italic")).pack()
    
    tk.Label(win, text="Target Email:").pack(pady=(10,0))
    target_email_entry = tk.Entry(win, width=40)
    target_email_entry.insert(0, "target@example.com")
    target_email_entry.pack(pady=2)
    
    tk.Label(win, text="Jumlah Email (Simulasi):").pack(pady=(10,0))
    num_emails_entry = tk.Entry(win, width=10)
    num_emails_entry.insert(0, "10")
    num_emails_entry.pack(pady=2)
    
    output_label = tk.Label(win, text="", wraplength=400, justify=tk.LEFT)
    output_label.pack(pady=10)
    
    def simulate_email_bomb():
        target = target_email_entry.get().strip()
        try:
            num = int(num_emails_entry.get().strip())
        except ValueError:
            messagebox.showwarning("Input Salah", "Jumlah email harus angka.")
            return
        
        if not target:
            messagebox.showwarning("Input Kosong", "Masukkan alamat email target.")
            return

        output_label.config(text=f"Mulai simulasi pengiriman {num} email ke {target}...\n\n")
        
        for i in range(1, num + 1):
            output_label.config(text=output_label.cget("text") + f"  [Simulasi]: Mengirim email {i}/{num}...\n")
            win.update_idletasks()
            time.sleep(0.05)
        
        output_label.config(text=output_label.cget("text") + "\nSimulasi pengiriman email selesai.")
        
    tk.Button(win, text="Mulai Bomb (Simulasi)", command=simulate_email_bomb, width=20).pack(pady=10)
    tk.Button(win, text="Tutup", command=win.destroy, width=10).pack(pady=5)

def webcam_hacking_simulator(parent=None):
    win = tk.Toplevel()
    win.title("19. Webcam Hacking Simulator (Simulasi)")
    win.geometry("400x300")

    tk.Label(win, text="Simulasi Akses Webcam", font=("Segoe UI", 10)).pack(pady=10)
    tk.Label(win, text="(Tidak ada webcam yang benar-benar diakses)", font=("Segoe UI", 8, "italic")).pack()

    status_label = tk.Label(win, text="Status: Tidak Aktif", font=("Segoe UI", 12, "bold"), fg="red")
    status_label.pack(pady=20)

    webcam_frame = tk.Frame(win, width=200, height=150, bd=2, relief="sunken", bg="gray")
    webcam_frame.pack(pady=10)
    tk.Label(webcam_frame, text="[Simulasi Feed Webcam]", fg="white", bg="gray").pack(expand=True)

    def simulate_access():
        status_label.config(text="Status: Mengakses Webcam (Simulasi)...", fg="orange")
        win.update_idletasks()
        time.sleep(1.5)
        status_label.config(text="Status: Webcam Diakses (Simulasi) ✅", fg="green")
        messagebox.showinfo("Simulasi Berhasil", "Webcam simulasi berhasil diakses!\n\n(Ini hanya simulasi. Webcam Anda aman.)")

    tk.Button(win, text="Simulasikan Akses", command=simulate_access, width=15).pack(pady=10)
    tk.Button(win, text="Tutup", command=win.destroy, width=10).pack(pady=5)

def ransomware_simulation(parent=None):
    win = tk.Toplevel()
    win.title("20. Ransomware Simulation (Simulasi)")
    win.geometry("600x450")

    tk.Label(win, text="Simulasi Serangan Ransomware", font=("Segoe UI", 10)).pack(pady=5)
    tk.Label(win, text="(Tidak ada file Anda yang akan dienkripsi)", font=("Segoe UI", 8, "italic")).pack()

    file_list_label = tk.Label(win, text="Daftar File (Simulasi):", anchor="w")
    file_list_label.pack(fill="x", padx=10, pady=(10,0))
    
    file_list_text = scrolledtext.ScrolledText(win, wrap=tk.WORD, width=70, height=10)
    file_list_text.pack(padx=10, pady=5)
    
    simulated_files = [
        "dokumen_penting.docx", "foto_liburan.jpg", "data_keuangan.xlsx",
        "catatan_rahasia.txt", "video_keluarga.mp4", "aplikasi.exe"
    ]
    file_list_text.insert(tk.END, "\n".join(simulated_files))
    file_list_text.config(state=tk.DISABLED)

    ransom_note_label = tk.Label(win, text="", wraplength=550, justify=tk.CENTER, fg="red", font=("Segoe UI", 10, "bold"))
    
    def simulate_ransomware():
        file_list_text.config(state=tk.NORMAL)
        file_list_text.delete("1.0", tk.END)
        encrypted_files = []
        
        ransom_note_text = ("!!! FILE ANDA TELAH DIENKRIPSI !!!\n"
                            "Semua dokumen, foto, dan file penting Anda telah dienkripsi.\n"
                            "Tidak ada cara untuk mengembalikan data Anda tanpa kunci dekripsi unik.\n"
                            "Untuk mendapatkan kembali file Anda, BAYAR sejumlah X Bitcoin ke alamat ini: [Alamat Bitcoin Palsu].\n"
                            "Anda hanya punya 48 jam. Jika tidak, kunci akan dihapus selamanya.\n"
                            "Jangan mencoba memulihkan sendiri - data Anda bisa rusak permanen.\n"
                            "\n[INI ADALAH SIMULASI UNTUK TUJUAN EDUKASI SAJA]")
        ransom_note_label.config(text=ransom_note_text)
        ransom_note_label.pack(pady=10)

        for f in simulated_files:
            encrypted_files.append(f"{f}.ENCRYPTED")
            file_list_text.insert(tk.END, f"{f} -> {f}.ENCRYPTED (Simulasi Enkripsi)\n")
            win.update_idletasks()
            time.sleep(0.1)
        file_list_text.config(state=tk.DISABLED)
        messagebox.showinfo("Ransomware (Simulasi)", "Simulasi enkripsi file selesai!")
    
    tk.Button(win, text="Simulasikan Serangan Ransomware", command=simulate_ransomware, width=30).pack(pady=10)
    tk.Button(win, text="Tutup", command=win.destroy, width=10).pack(pady=5)

def custom_exploit_development_sim(parent=None):
    win = tk.Toplevel()
    win.title("21. Custom Exploit Dev. (Simulasi)")
    win.geometry("500x400")

    tk.Label(win, text="Simulasi Pengembangan Eksploitasi Kustom", font=("Segoe UI", 10)).pack(pady=5)
    
    tk.Label(win, text="Jenis Kerentanan (contoh: Buffer Overflow):").pack(pady=(10,0))
    vuln_type_entry = tk.Entry(win, width=40)
    vuln_type_entry.insert(0, "Buffer Overflow")
    vuln_type_entry.pack(pady=2)

    tk.Label(win, text="Aplikasi Target (contoh: App Dummy v1.0):").pack(pady=(10,0))
    target_app_entry = tk.Entry(win, width=40)
    target_app_entry.insert(0, "App Dummy v1.0")
    target_app_entry.pack(pady=2)
    
    output_text = scrolledtext.ScrolledText(win, wrap=tk.WORD, width=55, height=10)
    output_text.pack(padx=10, pady=10)
    
    def simulate_exploit_dev():
        v_type = vuln_type_entry.get().strip()
        t_app = target_app_entry.get().strip()
        
        if not v_type or not t_app:
            messagebox.showwarning("Input Kosong", "Masukkan jenis kerentanan dan aplikasi target.")
            return

        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, f"Menganalisis '{v_type}' pada '{t_app}' (simulasi)...\n")
        win.update_idletasks()
        time.sleep(0.5)
        output_text.insert(tk.END, "  - Mengidentifikasi offset...\n")
        win.update_idletasks()
        time.sleep(0.5)
        output_text.insert(tk.END, "  - Membuat shellcode dummy (ukuran acak)...\n")
        win.update_idletasks()
        time.sleep(0.5)
        output_text.insert(tk.END, "  - Membangun payload eksploitasi simulasi...\n")
        win.update_idletasks()
        time.sleep(1)
        
        exploit_payload = f"Payload eksploitasi dummy untuk {v_type} di {t_app} (ukuran: {random.randint(100,500)} byte)"
        
        output_text.insert(tk.END, f"\n[HASIL SIMULASI] Eksploitasi dummy berhasil dikembangkan:\n")
        output_text.insert(tk.END, f"  Tipe Kerentanan: {v_type}\n")
        output_text.insert(tk.END, f"  Aplikasi Target: {t_app}\n")
        output_text.insert(tk.END, f"  Payload Eksploitasi: '{exploit_payload}'\n")
        output_text.see(tk.END)

    tk.Button(win, text="Mulai Pengembangan (Simulasi)", command=simulate_exploit_dev, width=25).pack(pady=10)
    tk.Button(win, text="Tutup", command=win.destroy, width=10).pack(pady=5)

def reverse_shell_sim(parent=None):
    win = tk.Toplevel()
    win.title("22. Reverse Shell (Simulasi)")
    win.geometry("600x450")

    tk.Label(win, text="Simulasi Koneksi Reverse Shell", font=("Segoe UI", 10)).pack(pady=5)
    tk.Label(win, text="(Tidak ada koneksi jaringan nyata yang dibuat)", font=("Segoe UI", 8, "italic")).pack()

    output_text = scrolledtext.ScrolledText(win, wrap=tk.WORD, width=70, height=15, bg="black", fg="lime green", insertbackground="lime green")
    output_text.pack(padx=10, pady=5)
    
    input_frame = tk.Frame(win)
    input_frame.pack(padx=10, pady=5, fill="x")
    
    prompt_label = tk.Label(input_frame, text="target_host_1> ", bg="black", fg="lime green")
    prompt_label.pack(side=tk.LEFT)
    
    command_entry = tk.Entry(input_frame, width=60, bg="black", fg="lime green", insertbackground="lime green")
    command_entry.pack(side=tk.LEFT, fill="x", expand=True)
    
    def process_command(event=None):
        cmd = command_entry.get().strip()
        command_entry.delete(0, tk.END)
        output_text.insert(tk.END, f"\n{prompt_label.cget('text')}{cmd}\n")
        
        if cmd.lower() == 'exit':
            output_text.insert(tk.END, "[SIMULASI] Koneksi reverse shell ditutup.\n")
            output_text.config(state=tk.DISABLED)
            command_entry.config(state=tk.DISABLED)
            prompt_label.config(text="")
            return
        elif cmd.lower() == 'ls' or cmd.lower() == 'dir':
            output_text.insert(tk.END, "file1.txt  folder_a/  program.exe  secret_doc.pdf\n")
        elif cmd.lower() == 'whoami':
            output_text.insert(tk.END, "simulated_user\n")
        elif cmd.lower() == 'pwd':
            output_text.insert(tk.END, "/home/simulated_user\n")
        else:
            output_text.insert(tk.END, f"Perintah '{cmd}' dieksekusi di target simulasi (output dummy).\n")
        output_text.see(tk.END)

    command_entry.bind("<Return>", process_command)
    
    output_text.insert(tk.END, "[SIMULASI] Menunggu koneksi dari target...\n")
    win.update_idletasks()
    time.sleep(1)
    output_text.insert(tk.END, "  Target simulasi: 'target_host_1' (IP: 192.168.1.100)\n")
    win.update_idletasks()
    time.sleep(1)
    output_text.insert(tk.END, "\n[SIMULASI] Koneksi masuk dari 192.168.1.100:12345 (target_host_1)!\n")
    output_text.insert(tk.END, "  Selamat datang di shell target simulasi.\n")
    output_text.insert(tk.END, "Anda sekarang berada di shell target simulasi. Ketik 'exit' untuk keluar.\n")
    output_text.see(tk.END)
    
    tk.Button(win, text="Tutup", command=win.destroy, width=10).pack(pady=5)

def advanced_keylogger_sim(parent=None):
    win = tk.Toplevel()
    win.title("23. Adv. Keylogger (Simulasi)")
    win.geometry("600x450")

    tk.Label(win, text="Simulasi Keylogger Canggih dengan Pengiriman Log", font=("Segoe UI", 10)).pack(pady=5)
    tk.Label(win, text="(Tidak ada penekanan tombol nyata yang direkam atau email yang dikirim)", font=("Segoe UI", 8, "italic")).pack()

    tk.Label(win, text="Simulasi Input yang Direkam:").pack(pady=(10,0))
    recorded_input_text = scrolledtext.ScrolledText(win, wrap=tk.WORD, width=65, height=8)
    recorded_input_text.pack(padx=10, pady=5)
    recorded_input_text.insert(tk.END, "username: dummyuser\npassword: P@ssw0rd123!\nemail: my.account@example.com\nsecret_note: This is a test message.")
    recorded_input_text.config(state=tk.DISABLED)
    
    tk.Label(win, text="Email Tujuan Log Simulasi:").pack(pady=(10,0))
    email_target_entry = tk.Entry(win, width=40)
    email_target_entry.insert(0, "log_receiver@example.com")
    email_target_entry.pack(pady=2)

    output_label = tk.Label(win, text="", wraplength=550, justify=tk.LEFT)
    output_label.pack(pady=10)

    def simulate_send_log():
        email = email_target_entry.get().strip()
        if not email:
            messagebox.showwarning("Input Kosong", "Masukkan alamat email tujuan.")
            return

        log_content = recorded_input_text.get("1.0", tk.END).strip()
        
        output_label.config(text=f"Menyimpan log yang direkam (simulasi)...\n")
        win.update_idletasks()
        time.sleep(0.8)
        output_label.config(text=output_label.cget("text") + f"Log disimpan secara lokal ke 'advanced_keylog_sim.txt' (simulasi).\n\n")
        win.update_idletasks()
        time.sleep(0.8)
        
        output_label.config(text=output_label.cget("text") + f"Mengirim log ke '{email}' via server SMTP dummy (simulasi)...\n")
        win.update_idletasks()
        time.sleep(1.5)
        output_label.config(text=output_label.cget("text") + "Email log simulasi berhasil 'terkirim'!\n\n")
        output_label.config(text=output_label.cget("text") + "Peringatan: Ini adalah simulasi. Keylogger nyata berbahaya dan ilegal.")
        
    tk.Button(win, text="Simulasikan Kirim Log via Email", command=simulate_send_log, width=30).pack(pady=10)
    tk.Button(win, text="Tutup", command=win.destroy, width=10).pack(pady=5)

def vulnerability_scanner_sim(parent=None):
    win = tk.Toplevel()
    win.title("24. Vulnerability Scanner (Simulasi)")
    win.geometry("700x500")

    tk.Label(win, text="Simulasi Pemindaian Kerentanan", font=("Segoe UI", 10)).pack(pady=5)
    tk.Label(win, text="(Tidak ada pemindaian jaringan/aplikasi nyata)", font=("Segoe UI", 8, "italic")).pack()

    tk.Label(win, text="Target untuk Dipindai (contoh: scan.example.com):").pack(pady=(10,0))
    target_entry = tk.Entry(win, width=50)
    target_entry.insert(0, "scan.example.com")
    target_entry.pack(pady=2)
    
    output_text = scrolledtext.ScrolledText(win, wrap=tk.WORD, width=80, height=18)
    output_text.pack(padx=10, pady=10)
    
    def scan_vulnerabilities():
        target = target_entry.get().strip()
        if not target:
            messagebox.showwarning("Input Kosong", "Masukkan target untuk dipindai.")
            return

        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, f"Memulai pemindaian kerentanan pada {target} (simulasi)...\n\n")
        win.update_idletasks()
        time.sleep(1)
        
        vulnerabilities = [
            {"name": "XSS (Cross-Site Scripting)", "severity": "Medium", "path": "/search?q=<script>", "description": "Memungkinkan injeksi skrip berbahaya ke halaman web."},
            {"name": "SQL Injection", "severity": "High", "path": "/login.php?id=' OR 1=1--", "description": "Memungkinkan eksekusi perintah SQL berbahaya melalui input."},
            {"name": "Directory Traversal", "severity": "Medium", "path": "/download?file=../../../../etc/passwd", "description": "Akses ke file dan direktori di luar batas yang dimaksudkan."},
            {"name": "Outdated Software (Apache 2.2)", "severity": "Low", "path": "/", "description": "Penggunaan versi perangkat lunak yang sudah usang dengan kerentanan yang diketahui."},
            {"name": "Open Port 8080 (Non-HTTP)", "severity": "Info", "path": "8080/tcp", "description": "Port terbuka yang mungkin tidak dimaksudkan untuk akses publik atau dikonfigurasi dengan aman."},
            {"name": "Weak Credentials", "severity": "High", "path": "/admin/login", "description": "Penggunaan kombinasi username/password yang mudah ditebak atau default."},
            {"name": "CSRF (Cross-Site Request Forgery)", "severity": "Medium", "path": "/transfer_money", "description": "Serangan yang menyebabkan pengguna akhir melakukan tindakan yang tidak diinginkan pada aplikasi web yang saat ini mereka autentikasi."},
        ]
        
        found_vulns_count = 0
        output_text.insert(tk.END, "[HASIL PEMINDAIAN SIMULASI]:\n")
        for vuln in vulnerabilities:
            if random.random() > 0.3:
                output_text.insert(tk.END, f"  [Ditemukan]: {vuln['name']} (Severity: {vuln['severity']})\n")
                output_text.insert(tk.END, f"    Path/Lokasi: {vuln['path']}\n")
                output_text.insert(tk.END, f"    Deskripsi: {vuln['description']}\n\n")
                found_vulns_count += 1
            else:
                output_text.insert(tk.END, f"  [Tidak Ditemukan]: {vuln['name']} (simulasi)\n\n")
            win.update_idletasks()
            time.sleep(0.2)
        
        if found_vulns_count == 0:
            output_text.insert(tk.END, "  Tidak ada kerentanan signifikan yang ditemukan (simulasi).\n")
        
        output_text.insert(tk.END, "\nSimulasi pemindaian kerentanan selesai. Sistem Anda aman.\n")
        output_text.see(tk.END)

    tk.Button(win, text="Mulai Pindai Kerentanan (Simulasi)", command=scan_vulnerabilities, width=30).pack(pady=10)
    tk.Button(win, text="Tutup", command=win.destroy, width=10).pack(pady=5)

def pentesting_framework_sim(parent=None):
    win = tk.Toplevel()
    win.title("25. Pentesting Framework (Simulasi)")
    win.geometry("700x550")

    tk.Label(win, text="Simulasi Kerangka Kerja Pengujian Penetrasi (Metasploit)", font=("Segoe UI", 10)).pack(pady=5)
    tk.Label(win, text="(Tidak ada eksploitasi nyata yang dieksekusi)", font=("Segoe UI", 8, "italic")).pack()

    output_text = scrolledtext.ScrolledText(win, wrap=tk.WORD, width=80, height=20, bg="black", fg="lime green", insertbackground="lime green")
    output_text.pack(padx=10, pady=5)
    output_text.insert(tk.END, "[SIMULASI] Memuat kerangka kerja pengujian penetrasi...\n")
    
    command_entry_frame = tk.Frame(win, bg="black")
    command_entry_frame.pack(padx=10, pady=5, fill="x")
    
    prompt_label = tk.Label(command_entry_frame, text="msf > ", bg="black", fg="lime green")
    prompt_label.pack(side=tk.LEFT)
    
    command_entry = tk.Entry(command_entry_frame, width=70, bg="black", fg="lime green", insertbackground="lime green")
    command_entry.pack(side=tk.LEFT, fill="x", expand=True)

    session_active = False
    
    def process_msf_command(event=None):
        nonlocal session_active
        cmd = command_entry.get().strip()
        command_entry.delete(0, tk.END)
        output_text.insert(tk.END, f"{prompt_label.cget('text')}{cmd}\n")
        
        if not session_active:
            if "use exploit/multi/handler" in cmd.lower():
                output_text.insert(tk.END, "msf exploit(handler) > \n")
                prompt_label.config(text="msf exploit(handler) > ")
            elif "set payload" in cmd.lower():
                output_text.insert(tk.END, "payload => python/meterpreter/reverse_tcp\n")
            elif "set lhost" in cmd.lower():
                output_text.insert(tk.END, "LHOST => 127.0.0.1\n")
            elif "set lport" in cmd.lower():
                output_text.insert(tk.END, "LPORT => 4444\n")
            elif "exploit" in cmd.lower():
                output_text.insert(tk.END, "\n[SIMULASI] Menunggu sesi Meterpreter...\n")
                win.update_idletasks()
                time.sleep(1.5)
                if random.random() > 0.3:
                    output_text.insert(tk.END, "\n[SIMULASI] Sesi Meterpreter 1 dibuka (192.168.1.100:12345 -> 127.0.0.1:4444)!\n")
                    output_text.insert(tk.END, "meterpreter > \n")
                    prompt_label.config(text="meterpreter > ")
                    session_active = True
                else:
                    output_text.insert(tk.END, "[SIMULASI] Tidak ada sesi yang masuk. Eksploitasi mungkin gagal.\n")
                    prompt_label.config(text="msf exploit(handler) > ")
            else:
                output_text.insert(tk.END, "Perintah tidak dikenali dalam simulasi msf ini.\n")
        elif session_active: # Meterpreter session
            if cmd.lower() == 'sysinfo':
                output_text.insert(tk.END, "    Computer        : TARGET_VM_SIM\n")
                output_text.insert(tk.END, "    OS              : Linux target-os (simulasi)\n")
                output_text.insert(tk.END, "    Architecture    : x64\n")
            elif cmd.lower() == 'shell':
                output_text.insert(tk.END, "\nSpawning shell on target (simulasi)...\n")
                output_text.insert(tk.END, "target_vm_sim:~# \n")
                prompt_label.config(text="target_vm_sim:~# ")
            elif cmd.lower() == 'exit':
                output_text.insert(tk.END, "[SIMULASI] Sesi Meterpreter ditutup.\n")
                session_active = False
                prompt_label.config(text="msf exploit(handler) > ")
            elif cmd.lower().startswith('cat /etc/passwd'):
                output_text.insert(tk.END, "root:x:0:0:root:/root:/bin/bash\nsimulated_user:x:1000:1000:Sim User:/home/simulated_user:/bin/bash\n")
            else:
                output_text.insert(tk.END, f"Perintah '{cmd}' dieksekusi di target simulasi (output dummy).\n")
        output_text.see(tk.END)
        
    command_entry.bind("<Return>", process_msf_command)
    
    win.update_idletasks()
    time.sleep(0.5)
    output_text.insert(tk.END, "msf > \n")
    output_text.see(tk.END)
    
    tk.Button(win, text="Tutup", command=win.destroy, width=10).pack(pady=5)

def botnet_development_sim(parent=None):
    win = tk.Toplevel()
    win.title("26. Botnet Development (Simulasi)")
    win.geometry("600x450")

    tk.Label(win, text="Simulasi Pengembangan Jaringan Bot", font=("Segoe UI", 10)).pack(pady=5)
    tk.Label(win, text="(Tidak ada bot nyata yang dibuat atau dikendalikan)", font=("Segoe UI", 8, "italic")).pack()

    output_text = scrolledtext.ScrolledText(win, wrap=tk.WORD, width=70, height=15)
    output_text.pack(padx=10, pady=5)

    num_bots = random.randint(5, 15)
    bots_sim = [{"id": i, "status": "online", "ip": f"10.0.0.{random.randint(1,254)}"} for i in range(1, num_bots + 1)]

    output_text.insert(tk.END, f"[SIMULASI] Menginisialisasi {num_bots} 'bot' dummy...\n")
    win.update_idletasks()
    time.sleep(1)
    output_text.insert(tk.END, "  Bot berhasil terhubung ke server C2 (Command & Control) simulasi.\n")
    output_text.see(tk.END)

    tk.Label(win, text="Masukkan perintah untuk bot (contoh: 'ping example.com', 'ddos'):").pack(pady=(10,0))
    command_entry = tk.Entry(win, width=50)
    command_entry.pack(pady=2)

    def send_bot_command():
        cmd_to_send = command_entry.get().strip()
        if not cmd_to_send:
            messagebox.showwarning("Input Kosong", "Masukkan perintah untuk dikirim.")
            return

        output_text.insert(tk.END, f"\n[SIMULASI] Mengirim perintah '{cmd_to_send}' ke semua bot...\n")
        for bot in bots_sim:
            if random.random() > 0.1:
                output_text.insert(tk.END, f"  Bot {bot['id']} ({bot['ip']}): Menerima dan menjalankan '{cmd_to_send}' (simulasi).\n")
            else:
                output_text.insert(tk.END, f"  Bot {bot['id']} ({bot['ip']}): Gagal menjalankan perintah (offline/error simulasi).\n")
            win.update_idletasks()
            time.sleep(0.05)
        
        if cmd_to_send.lower() == 'ddos':
            output_text.insert(tk.END, "\n[SIMULASI] Serangan DDoS diluncurkan (dummy traffic).\n")
            output_text.insert(tk.END, "  Target: dummy-target.com (simulasi)\n")
            output_text.insert(tk.END, "  Hasil: Server dummy-target.com menunjukkan peningkatan beban (simulasi).\n")
        output_text.see(tk.END)
        command_entry.delete(0, tk.END)

    tk.Button(win, text="Kirim Perintah ke Bot", command=send_bot_command, width=20).pack(pady=10)
    tk.Button(win, text="Tutup", command=win.destroy, width=10).pack(pady=5)

def advanced_malware_simulation(parent=None):
    win = tk.Toplevel()
    win.title("27. Advanced Malware Sim. (GUI)")
    win.geometry("600x500")

    tk.Label(win, text="Simulasi Perilaku Malware Canggih", font=("Segoe UI", 10)).pack(pady=5)
    tk.Label(win, text="(Tidak ada malware nyata yang dieksekusi atau merusak sistem Anda)", font=("Segoe UI", 8, "italic")).pack()

    tk.Label(win, text="Jenis Malware Simulasi (contoh: Rootkit, Trojan):").pack(pady=(10,0))
    malware_type_entry = tk.Entry(win, width=40)
    malware_type_entry.insert(0, "Trojan")
    malware_type_entry.pack(pady=2)
    
    output_text = scrolledtext.ScrolledText(win, wrap=tk.WORD, width=70, height=18)
    output_text.pack(padx=10, pady=10)
    
    def simulate_malware():
        m_type = malware_type_entry.get().strip()
        if not m_type:
            messagebox.showwarning("Input Kosong", "Masukkan jenis malware simulasi.")
            return

        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, f"[SIMULASI] Meluncurkan '{m_type}'...\n")
        win.update_idletasks()
        time.sleep(1)
        
        actions = [
            ("Mencoba memodifikasi entri registry (dummy)...", 0.2),
            ("Mencoba menyisipkan kode ke proses lain (dummy)...", 0.3),
            ("Membuat koneksi keluar ke C2 (simulasi)...", 0.1),
            ("Mengenkripsi file dummy lokal (simulasi) & meminta tebusan...", 0.4),
            ("Mengumpulkan kredensial dummy (simulasi)...", 0.2),
        ]
        
        output_text.insert(tk.END, "\n[SIMULASI] Aksi Malware:\n")
        for desc, detection_chance in actions:
            output_text.insert(tk.END, f"  - {desc}\n")
            win.update_idletasks()
            time.sleep(0.8)
            if random.random() < detection_chance:
                output_text.insert(tk.END, "    [Deteksi]: Oleh solusi keamanan (simulasi)!\n\n")
            else:
                output_text.insert(tk.END, "    [Tidak Terdeteksi]: Berhasil melewati (simulasi bypass)\n\n")
            win.update_idletasks()
            time.sleep(0.5)
        
        output_text.insert(tk.END, "\nSimulasi perilaku malware canggih selesai. Sistem Anda aman.\n")
        output_text.see(tk.END)

    tk.Button(win, text="Mulai Simulasi Malware", command=simulate_malware, width=25).pack(pady=10)
    tk.Button(win, text="Tutup", command=win.destroy, width=10).pack(pady=5)

def advanced_dns_spoofing_sim(parent=None):
    win = tk.Toplevel()
    win.title("28. Advanced DNS Spoofing (Simulasi)")
    win.geometry("600x450")

    tk.Label(win, text="Simulasi Pembajakan DNS Tingkat Lanjut", font=("Segoe UI", 10)).pack(pady=5)
    tk.Label(win, text="(Tidak ada perubahan DNS nyata)", font=("Segoe UI", 8, "italic")).pack()

    output_text = scrolledtext.ScrolledText(win, wrap=tk.WORD, width=70, height=15)
    output_text.pack(padx=10, pady=5)
    
    spoof_entries = {
        "bank.example.com": "192.168.1.50",
        "social.example.net": "192.168.1.51",
        "update.os.com": "192.168.1.52"
    }

    def simulate_advanced_spoof():
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, "[SIMULASI] Mengkonfigurasi server DNS palsu untuk beberapa domain...\n")
        win.update_idletasks()
        time.sleep(1)
        
        output_text.insert(tk.END, "  Entri spoofing yang disimulasikan:\n")
        for domain, ip in spoof_entries.items():
            output_text.insert(tk.END, f"    {domain} -> {ip}\n")
        win.update_idletasks()
        time.sleep(1.5)
        
        output_text.insert(tk.END, "\n[SIMULASI] Memicu pembajakan DNS di jaringan target (misalnya melalui cache poisoning)...\n")
        win.update_idletasks()
        time.sleep(1.5)
        
        output_text.insert(tk.END, "\n--- Simulasi Kueri DNS dari Klien Target ---\n")
        for domain, fake_ip in spoof_entries.items():
            output_text.insert(tk.END, f"  Klien meminta '{domain}'...\n")
            win.update_idletasks()
            time.sleep(0.5)
            
            if random.random() > 0.2:
                output_text.insert(tk.END, f"    -> Menerima IP palsu: {fake_ip} (Sukses Spoof)\n\n")
            else:

                try:
                    real_ip = socket.gethostbyname(domain)
                    output_text.insert(tk.END, f"    -> Menerima IP asli: {real_ip} (Spoof Gagal/Terdeteksi)\n\n")
                except socket.gaierror:
                    output_text.insert(tk.END, f"    -> Tidak dapat me-resolve (Domain tidak ada/error)\n\n")
            win.update_idletasks()
            time.sleep(0.5)
            
        output_text.insert(tk.END, "\nSimulasi pembajakan DNS tingkat tinggi selesai.\n")
        output_text.see(tk.END)

    tk.Button(win, text="Mulai Simulasi DNS Spoof Tingkat Lanjut", command=simulate_advanced_spoof, width=35).pack(pady=10)
    tk.Button(win, text="Tutup", command=win.destroy, width=10).pack(pady=5)

def fileless_malware_sim(parent=None):
    win = tk.Toplevel()
    win.title("29. Fileless Malware (Simulasi)")
    win.geometry("600x450")

    tk.Label(win, text="Simulasi Malware Tanpa File", font=("Segoe UI", 10)).pack(pady=5)
    tk.Label(win, text="(Tidak ada kode berbahaya nyata yang dimuat ke memori)", font=("Segoe UI", 8, "italic")).pack()

    output_text = scrolledtext.ScrolledText(win, wrap=tk.WORD, width=70, height=18)
    output_text.pack(padx=10, pady=10)
    
    def simulate_fileless_malware():
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, "[SIMULASI] Serangan dimulai. Memuat payload ke memori...\n")
        win.update_idletasks()
        time.sleep(1.5)
        
        techniques = [
            "Injeksi kode ke PowerShell (simulasi)",
            "Memanfaatkan WMI (Windows Management Instrumentation) (simulasi)",
            "Menyisipkan payload ke proses legitimate (simulasi)",
            "Menggunakan script dalam registry (simulasi)",
            "Memanfaatkan teknik reflektif (simulasi)"
        ]
        
        executed_techniques = random.sample(techniques, k=random.randint(2, len(techniques)))
        
        output_text.insert(tk.END, "\n[SIMULASI] Teknik yang dieksekusi dalam memori:\n")
        for tech in executed_techniques:
            output_text.insert(tk.END, f"  - {tech}\n")
            win.update_idletasks()
            time.sleep(0.8)
            if random.random() > 0.6:
                output_text.insert(tk.END, "    [Deteksi]: Oleh solusi keamanan memori (simulasi)!\n\n")
            else:
                output_text.insert(tk.END, "    [Tidak Terdeteksi]: Berhasil menghindari deteksi awal (simulasi)\n\n")
            win.update_idletasks()
            time.sleep(0.5)
        
        output_text.insert(tk.END, "\n[SIMULASI] Malware tanpa file telah menjalankan tugasnya dan menghilang dari memori.\n")
        output_text.insert(tk.END, "Peringatan: Malware tanpa file sangat sulit dideteksi oleh antivirus tradisional.")
        output_text.see(tk.END)

    tk.Button(win, text="Mulai Simulasi Malware Tanpa File", command=simulate_fileless_malware, width=30).pack(pady=10)
    tk.Button(win, text="Tutup", command=win.destroy, width=10).pack(pady=5)

def automated_osint_tool_sim(parent=None):
    win = tk.Toplevel()
    win.title("30. Automated OSINT Tool (Simulasi)")
    win.geometry("650x550")

    tk.Label(win, text="Simulasi Alat OSINT Otomatis", font=("Segoe UI", 10)).pack(pady=5)
    tk.Label(win, text="(Hanya mengumpulkan informasi dummy dari sumber simulasi)", font=("Segoe UI", 8, "italic")).pack()

    tk.Label(win, text="Nama/Entitas Target untuk OSINT (contoh: John Doe, Perusahaan XYZ):").pack(pady=(10,0))
    target_name_entry = tk.Entry(win, width=50)
    target_name_entry.insert(0, "John Doe")
    target_name_entry.pack(pady=2)
    
    output_text = scrolledtext.ScrolledText(win, wrap=tk.WORD, width=75, height=20)
    output_text.pack(padx=10, pady=10)
    
    def simulate_osint():
        target_name = target_name_entry.get().strip()
        if not target_name:
            messagebox.showwarning("Input Kosong", "Masukkan nama/entitas target.")
            return

        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, f"[SIMULASI] Mengumpulkan informasi OSINT untuk '{target_name}'...\n")
        win.update_idletasks()
        
        data_sources = [
            "Media Sosial Publik",
            "Pencarian Web/Mesin Pencari",
            "Data Pelanggaran (simulasi)",
            "Informasi Registrasi Domain",
            "Forum Publik & Blog",
            "Basis Data Publik (simulasi)"
        ]
        
        collected_info = {}
        output_text.insert(tk.END, "\n[SIMULASI] Data yang dikumpulkan:\n")
        for source in data_sources:
            output_text.insert(tk.END, f"  Mencari di {source}...\n")
            win.update_idletasks()
            time.sleep(0.8)
            
            if random.random() > 0.3:
                info_points = random.randint(1, 3)
                info_list = []
                for _ in range(info_points):
                    if "Media Sosial" in source:
                        info_list.append(f"Profil ditemukan: fb.com/{target_name.replace(' ', '_')}_{random.randint(1,99)}")
                    elif "Pencarian Web" in source:
                        info_list.append(f"Artikel/berita relevan: 'Tentang {target_name}' link_dummy_{random.randint(1,99)}")
                    elif "Data Pelanggaran" in source:
                        info_list.append(f"Email ditemukan di pelanggaran: {target_name.split(' ')[0].lower()}{random.randint(1,99)}@email.com")
                    elif "Registrasi Domain" in source:
                        info_list.append(f"Domain terkait: {target_name.replace(' ', '').lower()}{random.randint(1,99)}.com")
                    elif "Forum" in source:
                        info_list.append(f"Postingan relevan: post_id_{random.randint(1,99)} dari forum_cyber_sim")
                    elif "Basis Data Publik" in source:
                         info_list.append(f"Alamat simulasi: Jl. Dummy No.{random.randint(1,100)}")

                collected_info[source] = info_list
                for item in info_list:
                    output_text.insert(tk.END, f"    - {item}\n")
            else:
                output_text.insert(tk.END, "    Tidak ada informasi relevan yang ditemukan (simulasi).\n")
            win.update_idletasks()
            time.sleep(0.5)
                
        output_text.insert(tk.END, "\n--- Ringkasan Laporan OSINT (Simulasi) ---\n")
        if collected_info:
            for source, items in collected_info.items():
                output_text.insert(tk.END, f"\nDari {source}:\n")
                for item in items:
                    output_text.insert(tk.END, f"  - {item}\n")
        else:
            output_text.insert(tk.END, "Tidak ada informasi yang berhasil dikumpulkan (simulasi).\n")
        output_text.see(tk.END)
        output_text.insert(tk.END, "\nSimulasi alat OSINT otomatis selesai. Data yang ditampilkan adalah dummy.\n")

    tk.Button(win, text="Mulai Pengumpulan OSINT (Simulasi)", command=simulate_osint, width=30).pack(pady=10)
    tk.Button(win, text="Tutup", command=win.destroy, width=10).pack(pady=5)

# --- Splash screen ---
def show_splash(root_callable, duration=2.2):
    splash = tk.Tk()
    splash.overrideredirect(True)
    w, h = 460, 240
    x = (splash.winfo_screenwidth() // 2) - (w // 2)
    y = (splash.winfo_screenheight() // 2) - (h // 2)
    splash.geometry(f"{w}x{h}+{x}+{y}")
    frame = tk.Frame(splash, bg="#072630")
    frame.pack(fill=tk.BOTH, expand=True)
    tk.Label(frame, text="Cyber Tools", font=("Segoe UI", 22, "bold"), bg="#072630", fg="#d1f1ff").pack(pady=(30,6))
    tk.Label(frame, text="Educational / Simulation Suite", font=("Segoe UI", 10), bg="#072630", fg="#bfe7ff").pack()
    prog = tk.Canvas(frame, width=380, height=18, bg="#0b2f3a", highlightthickness=0)
    prog.pack(pady=18)
    rect = prog.create_rectangle(0, 0, 0, 0, fill="#34c2eb")
    steps = 40
    for i in range(steps):
        prog.coords(rect, (0, 0, int((i+1)/steps*380), 18))
        splash.update_idletasks()
        time.sleep(duration/steps)
    splash.destroy()
    root_callable()

# --- Main GUI ---
def main_app():
    if HAS_TTB:
        app = ttk.Window(themename='cyborg')
        root = app
    else:
        root = tk.Tk()
        root.title("Cyber Tools")

        root.geometry("1250x680")

    try:
        if ICON_PNG.exists():
            img = PhotoImage(file=str(ICON_PNG))
            root.iconphoto(False, img)
    except Exception:
        pass

    tk.Label(root, text="Cyber Tools", font=("Segoe UI", 18, "bold")).pack(pady=10)
    tk.Label(root, text="Educational / Simulation Suite", font=("Segoe UI", 9)).pack(pady=(0,8))

    container = tk.Frame(root)
    container.pack(padx=18, pady=4, fill=tk.BOTH, expand=True)

    buttons_col1 = [
        ("1. Keylogger Sederhana", keylogger_safe),
        ("2. Port Scanner", port_scanner),
        ("3. Password Generator", password_generator),
        ("4. Brute Force (Dummy)", brute_force_dummy),
        ("5. Caesar Cipher", caesar_cipher),
        ("6. Website Crawler", website_crawler),
        ("7. MAC Changer (SIMULATION)", mac_changer_sim),
        ("8. Ping Tester", ping_tester),
        ("9. IP Locator", ip_locator),
        ("10. Screenshot Taker", screenshot_taker)
    ]

    buttons_col2 = [
        ("11. Packet Sniffer", packet_sniffer_sim),
        ("12. ARP Spoofer", arp_spoofer_sim),
        ("13. Subdomain Finder", subdomain_finder_sim),
        ("14. SQL Injection Sim.", sql_injection_simulator),
        ("15. DNS Spoofer", dns_spoofer_sim),
        ("16. Steganography Tool", steganography_tool_sim),
        ("17. Network Scanner", network_scanner_sim),
        ("18. Email Bomber", email_bomber_sim),
        ("19. Webcam Hacking Sim.", webcam_hacking_simulator),
        ("20. Ransomware Simulation", ransomware_simulation),
    ]

    buttons_col3 = [
        ("21. Custom Exploit Dev.", custom_exploit_development_sim),
        ("22. Reverse Shell", reverse_shell_sim),
        ("23. Advanced Keylogger", advanced_keylogger_sim),
        ("24. Vulnerability Scanner", vulnerability_scanner_sim),
        ("25. Pentesting Framework", pentesting_framework_sim),
        ("26. Botnet Development", botnet_development_sim),
        ("27. Advanced Malware Sim.", advanced_malware_simulation),
        ("28. Advanced DNS Spoofing", advanced_dns_spoofing_sim),
        ("29. Fileless Malware", fileless_malware_sim),
        ("30. Automated OSINT Tool", automated_osint_tool_sim),
    ]

    container.grid_columnconfigure(0, weight=1)
    container.grid_columnconfigure(1, weight=1)
    container.grid_columnconfigure(2, weight=1)

    for i, (txt, fn) in enumerate(buttons_col1):
        if HAS_TTB:
            b = ttk.Button(container, text=txt, command=lambda f=fn: f(root), width=35, bootstyle="info")
        else:
            b = tk.Button(container, text=txt, command=lambda f=fn: f(root), width=35, height=2)
        b.grid(row=i, column=0, padx=6, pady=6, sticky="ew")

    for i, (txt, fn) in enumerate(buttons_col2):
        if HAS_TTB:
            b = ttk.Button(container, text=txt, command=lambda f=fn: f(root), width=35, bootstyle="info")
        else:
            b = tk.Button(container, text=txt, command=lambda f=fn: f(root), width=35, height=2)
        b.grid(row=i, column=1, padx=6, pady=6, sticky="ew")

    for i, (txt, fn) in enumerate(buttons_col3):
        if HAS_TTB:
            b = ttk.Button(container, text=txt, command=lambda f=fn: f(root), width=35, bootstyle="info")
        else:
            b = tk.Button(container, text=txt, command=lambda f=fn: f(root), width=35, height=2)
        b.grid(row=i, column=2, padx=6, pady=6, sticky="ew")

    if HAS_TTB:
        quit_btn = ttk.Button(root, text="Keluar", command=root.destroy, bootstyle="danger", width=12)
    else:
        quit_btn = tk.Button(root, text="Keluar", command=root.destroy, bg="#d9534f", fg="white", width=12, height=1)
    quit_btn.pack(pady=12)

    tk.Label(root, text="Dependencies (optional): requests, beautifulsoup4, ttkbootstrap, pyautogui", font=("Segoe UI", 8)).pack(side=tk.BOTTOM, pady=6)

    root.mainloop()

if __name__ == "__main__":
    try:
        show_splash(main_app, duration=2.2)
    except Exception:
        main_app()