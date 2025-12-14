import os
import socket
import random
import string
import requests
import pyautogui
import keyboard
import time
import json
import subprocess
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

RESET   = "\033[0m"
BOLD    = "\033[1m"

RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
BLUE    = "\033[94m"
MAGENTA = "\033[95m"
CYAN    = "\033[96m"
WHITE   = "\033[97m"

try:
    import keyboard
except ImportError:
    keyboard = None
    print("Peringatan: Modul 'keyboard' tidak ditemukan. Fitur Keylogger mungkin tidak berfungsi.")

try:
    import pyautogui
except ImportError:
    pyautogui = None
    print("Peringatan: Modul 'pyautogui' tidak ditemukan. Fitur Screenshot mungkin tidak berfungsi.")

def keylogger():
    print("\n--- 1. Keylogger Sederhana ---")

    if keyboard is None:
        print("[Keylogger] Modul 'keyboard' tidak terinstal. Fitur ini dinonaktifkan.")
        return
    
    print("[Keylogger Sederhana (Simulasi)] Tekan ENTER untuk berhenti merekam.")
    print("Ketik sesuatu di sini (akan disimpan ke keylog_sim.txt):")
    
    logged_text = ""
    start_time = time.time()
    
    while True:
        try:
            line = input()
            logged_text += line + "\n"
        except EOFError:
            break
        if not line:
            break
        
    end_time = time.time()
    
    file_name = "keylog_sim.txt"
    with open(file_name, "w") as f:
        f.write(f"--- Simulasi Log Keylogger ({time.ctime()}) ---\n")
        f.write(logged_text.strip() + "\n")
        f.write(f"Durasi simulasi: {int(end_time - start_time)} detik.\n")
    print(f"[Keylogger Simulasi] Input disimpan ke {file_name}")

def port_scanner():
    print("\n--- 2. Port Scanner ---")

    target = input("Masukkan IP atau Host: ")
    ports = [21,22,23,25,53,80,110,139,143,443,445,3389,8080]
    print(f"Memindai {target}...")
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(0.8)
            result = sock.connect_ex((target, port))
            if result == 0:
                print(f"Port {port} TERBUKA")
            else:
                print(f"Port {port} TERTUTUP/FILTERED")
            sock.close()
        except socket.gaierror:
            print(f"Host {target} tidak dapat di-resolve.")
            break
        except Exception as e:
            print(f"Error memindai port {port}: {e}")

def password_generator():
    print("\n--- 3. Password Generator ---")

    try:
        length = int(input("Panjang password (contoh: 16): "))
    except ValueError:
        print("Input salah. Panjang password harus angka.")
        return
    chars = string.ascii_letters + string.digits + string.punctuation
    password = "".join(random.choice(chars) for _ in range(length))
    print("Password yang dihasilkan:", password)

def brute_force_dummy():
    print("\n--- 4. Brute Force Login (Dummy) ---")

    user = "admin"
    correct_pass = "1234"
    attempts = 0
    print(f"[Brute Force (Dummy)] Mencoba brute force pada user: {user}...")
    
    start_time = time.time()
    for attempt_num in range(10000):
        guess = str(attempt_num).zfill(4)
        attempts += 1
        print(f"  Mencoba: {guess}...", end='\r') 
        time.sleep(0.001) 
        if guess == correct_pass:
            print(f"\n[SUKSES] Password ditemukan: {guess} setelah {attempts} percobaan (SIMULASI)")
            break
    else:
        print("\n[GAGAL] Password tidak ditemukan dalam 10000 percobaan (SIMULASI)")
    print(f"Simulasi selesai dalam {int(time.time() - start_time)} detik.")

def caesar_cipher():
    print("\n--- 5. Caesar Cipher Encoder/Decoder ---")

    choice = input("Encrypt (E) / Decrypt (D)? ").lower()
    if choice not in ['e', 'd']:
        print("Pilihan tidak valid. Masukkan 'E' atau 'D'.")
        return
    
    text = input("Masukkan teks: ")
    try:
        shift = int(input("Shift (angka): "))
    except ValueError:
        print("Input salah. Shift harus angka.")
        return
        
    result = ""
    for char in text:
        if char.isalpha():
            start = ord('A') if char.isupper() else ord('a')
            if choice == "e":
                result += chr((ord(char) - start + shift) % 26 + start)
            else:
                result += chr((ord(char) - start - shift) % 26 + start)
        else:
            result += char
    print("Hasil:", result)


def website_crawler():
    print("\n--- 6. Website Crawler ---")

    url = input("Masukkan URL (sertakan http/https): ").strip()

    if not url.startswith(("http://", "https://")):
        print("URL tidak valid. Harap sertakan http:// atau https://")
        return

    try:
        print(f"\nMengambil link dari {url}...\n")

        response = requests.get(url, timeout=10)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, "html.parser")

        links = set()

        for a in soup.find_all("a", href=True):
            full_url = urljoin(url, a["href"])
            parsed = urlparse(full_url)

            # hanya link http/https
            if parsed.scheme in ("http", "https"):
                links.add(full_url)

        if links:
            print(f"Ditemukan {len(links)} link:\n")
            for i, link in enumerate(list(links)[:20], start=1):
                print(f"{i}. {link}")

            if len(links) > 20:
                print(f"\n... dan {len(links) - 20} link lainnya.")
        else:
            print("Tidak ada link ditemukan di halaman ini.")

    except requests.exceptions.Timeout:
        print("Gagal mengambil halaman: koneksi timeout.")
    except requests.exceptions.RequestException as e:
        print(f"Gagal mengambil halaman: {e}")
    except Exception as e:
        print(f"Terjadi kesalahan: {e}")

def mac_changer_dummy():
    print("\n--- 7. MAC Address Changer (Dummy) ---")

    current_mac = "00:11:22:33:44:55"
    new_mac_sim = "02:1A:2B:3C:4D:5E"
    
    print(f"[MAC Changer (Simulasi)] MAC Address saat ini: {current_mac}")
    print(f"Menghasilkan MAC Address baru (Simulasi): {new_mac_sim}")
    print("\n--- PERHATIAN: Ini adalah SIMULASI ---")
    print("Perubahan MAC Address NYATA memerlukan hak akses administrator/root.")
    print("Perintah yang MUNGKIN perlu Anda jalankan (jangan jalankan ini jika Anda tidak tahu apa yang Anda lakukan!):")
    print(f"  Linux: sudo ifconfig <interface> down && sudo ifconfig <interface> hw ether {new_mac_sim} && sudo ifconfig <interface> up")
    print(f"  Windows: (melalui Device Manager atau Nmap/Third-party tools)")
    print(f"  macOS: sudo ifconfig en0 ether {new_mac_sim}")
    print(f"\n[SIMULASI] MAC Address berhasil diubah menjadi {new_mac_sim}")


def ping_tester():
    print("\n--- 8. Ping Tester ---")

    host = input("Masukkan host/IP untuk di-ping: ").strip()
    if not host:
        print(RED + "Host/IP tidak boleh kosong." + RESET)
        return

    print(YELLOW + f"\nMelakukan ping ke {host}...\n" + RESET)

    try:
        # Windows (-n), Linux/macOS (-c)
        if os.name == "nt":
            cmd = ["ping", "-n", "4", host]
        else:
            cmd = ["ping", "-c", "4", host]

        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # Output ping asli
        if result.stdout:
            print(result.stdout)

        # Status REAL berdasarkan returncode OS
        if result.returncode == 0:
            print(GREEN + "STATUS : HOST DAPAT DIJANGKAU ✔" + RESET)
        else:
            print(RED + "STATUS : HOST TIDAK DAPAT DIJANGKAU ✖" + RESET)
            if result.stderr:
                print(RED + "ERROR  : " + result.stderr.strip() + RESET)

    except FileNotFoundError:
        print(RED + "Perintah 'ping' tidak ditemukan di sistem." + RESET)
    except Exception as e:
        print(RED + f"Terjadi kesalahan: {e}" + RESET)

def ip_locator():
    print("\n--- 9. IP Address Locator ---")

    ip = input("Masukkan IP (kosong untuk IP Anda sendiri): ").strip()
    target = ip if ip else ""

    print(f"Mencari lokasi IP {target if target else 'Anda'}...\n")

    try:
        r = requests.get(f"http://ip-api.com/json/{target}", timeout=8).json()
        if r.get('status') == 'success':
            for k, v in r.items():
                print(f"{k.replace('_', ' ').title():20}: {v}")
        else:
            print(f"Gagal menemukan lokasi IP: {r.get('message', 'IP tidak valid atau tidak ditemukan.')}")
    except requests.exceptions.RequestException as e:
        print(f"Gagal mengambil data lokasi IP: {e}")
    except Exception as e:
        print(f"Terjadi kesalahan: {e}")

def screenshot_taker():
    print("\n--- 10. Screenshot Taker ---")

    if pyautogui is None:
        print("[Screenshot] Modul 'pyautogui' tidak terinstal. Fitur ini dinonaktifkan.")
        return
    
    file_name = input("Masukkan nama file untuk screenshot (contoh: screenshot.png): ") or "screenshot.png"
    print(f"[Screenshot] Mengambil screenshot dan menyimpan sebagai {file_name}...")
    try:
        pyautogui.screenshot(file_name)
        print(f"[Screenshot] Berhasil disimpan sebagai {file_name}")
    except Exception as e:
        print(f"[Screenshot] Gagal mengambil screenshot: {e}")

def packet_sniffer_sim_cli():
    print("\n--- 11. Packet Sniffer ---")
    print("Menangkap paket jaringan (simulasi, output acak)...")
    print("Tekan Ctrl+C untuk berhenti.")
    
    try:
        for i in range(random.randint(5, 15)):
            src_ip = ".".join(map(str, (random.randint(1,254) for _ in range(4))))
            dst_ip = ".".join(map(str, (random.randint(1,254) for _ in range(4))))
            src_port = random.randint(1024, 65535)
            dst_port = random.randint(1, 65535)
            protocol = random.choice(["TCP", "UDP", "ICMP"])
            data_size = random.randint(50, 1500)
            packet_type = random.choice(["HTTP", "DNS", "FTP", "SSH", "TLS"])
            
            print(f"[Waktu: {time.strftime('%H:%M:%S')}] {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Proto: {protocol} | Ukuran: {data_size} byte | Tipe: {packet_type}")
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nSimulasi Packet Sniffer dihentikan.")
    print("Simulasi Packet Sniffer selesai.")

def arp_spoofer_sim_cli():
    print("\n--- 12. ARP Spoofer (Simulasi CLI) ---")
    target_ip = input("Masukkan IP target yang akan di-spoof (contoh: 192.168.1.1): ") or "192.168.1.1"
    gateway_ip = input("Masukkan IP Gateway (contoh: 192.168.1.254): ") or "192.168.1.254"
    
    attacker_mac = "F0:E1:D2:C3:B4:A5"
    
    print("\n--- Cache ARP Awal (Simulasi) ---")
    print(f"  {target_ip}       00:1A:2B:3C:4D:5E")
    print(f"  {gateway_ip}     01:23:45:67:89:AB")
    print("\n--- Memicu Spoof ARP (Simulasi) ---")
    print(f"  Mengirim paket ARP palsu dari {attacker_mac} ke {target_ip} dan {gateway_ip}...")
    time.sleep(2)
    print("\n--- Cache ARP Setelah Spoof (Simulasi) ---")
    print(f"  {target_ip}       {attacker_mac} (TERUBAH)")
    print(f"  {gateway_ip}     {attacker_mac} (TERUBAH)")
    print(f"\n[SIMULASI] Komunikasi antara {target_ip} dan {gateway_ip} kini dapat melewati penyerang.")
    print("Penting: Ini hanyalah simulasi, tidak ada perubahan nyata pada jaringan Anda.")


def subdomain_finder_sim_cli():
    print("\n--- 13. Subdomain Finder ---")

    domain = input("Masukkan domain (contoh: example.com): ").strip()
    if not domain:
        print("Domain tidak boleh kosong.")
        return

    print(f"\nMencari subdomain untuk {domain}...\n")

    common_subdomains = [
        "www", "mail", "ftp", "blog", "dev", "test", "api",
        "admin", "secure", "panel", "webmail", "store"
    ]

    found = []

    for sub in common_subdomains:
        full_domain = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(full_domain)
            print(f"[Ditemukan] {full_domain} ➜ {ip}")
            found.append(full_domain)
        except socket.gaierror:
            print(f"[Tidak Ditemukan] {full_domain}")
        time.sleep(0.1)

    print("\n--- Hasil ---")
    if found:
        print(f"Ditemukan {len(found)} subdomain:")
        for d in found:
            print(f" - {d}")
    else:
        print("Tidak ada subdomain yang ditemukan.")

def sql_injection_simulator_cli():
    print("\n--- 14. SQL Injection Simulator ---")
    print("Simulasi login pada aplikasi web yang rentan.")
    
    username = input("Masukkan Username (coba 'admin' atau 'admin'--): ")
    password = input("Masukkan Password (coba 'password' atau 'OR 1=1--'): ")
    
    print("\n--- Query SQL yang Disimulasikan ---")
    # Simulate backend SQL query
    simulated_query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}';"
    print(simulated_query)
    
    print("\n--- Hasil Login Simulasi ---")
    if username == "admin" and password == "password":
        print("[SIMULASI] Login Berhasil! Selamat datang, admin.")
    elif username == "admin" and password == "OR 1=1--":
        print("[SIMULASI] SQL Injection Berhasil! Login tanpa password! Selamat datang, admin.")
    elif username == "admin' OR '1'='1" and password == "--":
        print("[SIMULASI] SQL Injection Berhasil! Login tanpa password! Selamat datang, admin.")
    else:
        print("[SIMULASI] Login Gagal. Username atau password salah.")
    print("\nPeringatan: Ini hanyalah simulasi untuk tujuan edukasi. Jangan mencoba ini pada sistem nyata tanpa izin!")

def dns_spoofer_sim_cli():
    print("\n--- 15. DNS Spoofer ---")
    print("Simulasi pembajakan DNS untuk mengarahkan domain ke IP palsu.")
    
    domain_target = input("Masukkan domain yang akan di-spoof (contoh: google.com): ") or "google.com"
    fake_ip = input("Masukkan IP palsu untuk diarahkan (contoh: 1.2.3.4): ") or "1.2.3.4"
    
    print("\n--- Proses Resolusi DNS Asli (Simulasi) ---")
    original_ip = "Tidak dapat me-resolve"
    try:
        original_ip = socket.gethostbyname(domain_target)
        print(f"  {domain_target} (asli) -> {original_ip}")
    except socket.gaierror:
        print(f"  {domain_target} tidak dapat di-resolve ke IP asli.")
        
    print("\n--- Setelah Pembajakan DNS (Simulasi) ---")
    print(f"  Server DNS palsu merespons '{domain_target}' dengan IP: {fake_ip}")
    print(f"\n[SIMULASI] Klien sekarang akan diarahkan ke {fake_ip} ketika mencoba mengakses {domain_target}.")
    print("Peringatan: Ini hanyalah simulasi. Tidak ada perubahan DNS yang sebenarnya terjadi.")

def steganography_tool_sim_cli():
    print("\n--- 16. Steganography Tool ---")
    print("Menyembunyikan atau mengekstrak pesan dalam data gambar (simulasi).")
    
    action = input("Sembunyikan (S) atau Ekstrak (E) pesan? ").lower()
    if action not in ['s', 'e']:
        print("Pilihan tidak valid. Pilih 'S' atau 'E'.")
        return
        
    if action == 's':
        message = input("Masukkan pesan untuk disembunyikan: ")
        image_data_sim = "Ini adalah data gambar dummy 12345."
        
        simulated_embedded_data = image_data_sim + f" [EMBEDDED_MESSAGE:{message}]"
        print("\n--- Hasil Penyembunyian (Simulasi) ---")
        print("Pesan Anda telah 'disembunyikan' dalam data gambar simulasi.")
        print(f"Data Gambar dengan Pesan (Simulasi): '{simulated_embedded_data}'")
        print("Anda dapat mencoba mengekstraknya menggunakan opsi 'E'.")
    else: # action == 'e'
        embedded_data_input = input("Masukkan data gambar simulasi yang mengandung pesan: ")
        print("\n--- Hasil Ekstraksi (Simulasi) ---")
        if "[EMBEDDED_MESSAGE:" in embedded_data_input:
            start_idx = embedded_data_input.find("[EMBEDDED_MESSAGE:") + len("[EMBEDDED_MESSAGE:")
            end_idx = embedded_data_input.find("]", start_idx)
            if end_idx != -1:
                extracted_message = embedded_data_input[start_idx:end_idx]
                print(f"Pesan yang diekstrak: '{extracted_message}'")
            else:
                print("Format pesan tersembunyi tidak valid.")
        else:
            print("Tidak ada pesan tersembunyi yang ditemukan dalam data simulasi ini.")
    print("Penting: Ini hanyalah simulasi, tidak ada gambar nyata yang diproses.")

def network_scanner_sim_cli():
    print("\n--- 17. Network Scanner ---")
    print("Memindai perangkat di jaringan lokal (simulasi)...")
    
    base_ip = "192.168.1."
    print("\nDaftar Perangkat yang Ditemukan (Simulasi):")
    for i in range(1, 15):
        ip = f"{base_ip}{i}"
        hostname = f"host-{i}.local" if random.random() > 0.3 else "N/A"
        status = random.choice(["Online", "Offline"])
        open_ports = []
        if status == "Online":
            open_ports = random.sample(["80", "443", "22", "21", "3389", "8080", "53"], k=random.randint(0,3))
        
        print(f"\nIP: {ip}")
        print(f"  Hostname: {hostname}")
        print(f"  Status: {status}")
        print(f"  Port Terbuka (Simulasi): {', '.join(open_ports) if open_ports else 'Tidak ada'}")
        time.sleep(0.1)
            
    print("\nSimulasi pemindaian jaringan selesai.")
    print("Penting: Ini hanyalah simulasi. Tidak ada pemindaian jaringan nyata yang dilakukan.")

def email_bomber_sim_cli():
    print("\n--- 18. Email Bomber ---")
    print("Mengirim email massal (simulasi). Tidak ada email yang benar-benar dikirim!")
    
    target_email = input("Masukkan alamat email target (contoh: target@example.com): ")
    if not target_email:
        print("Alamat email tidak boleh kosong.")
        return
        
    try:
        num_emails = int(input("Masukkan jumlah email simulasi yang akan dikirim: "))
    except ValueError:
        print("Jumlah email harus angka.")
        return
        
    print(f"\nMulai simulasi pengiriman {num_emails} email ke {target_email}...")
    for i in range(1, num_emails + 1):
        print(f"  [Simulasi]: Mengirim email {i}/{num_emails}...")
        time.sleep(0.05)
        
    print(f"\nSimulasi pengiriman {num_emails} email ke {target_email} selesai.")
    print("Penting: Ini hanyalah simulasi. Tidak ada email nyata yang terkirim.")

def webcam_hacking_simulator_cli():
    print("\n--- 19. Webcam Hacking Simulator ---")
    print("Mencoba mengakses webcam (simulasi). Tidak ada webcam nyata yang diakses!")
    
    print("\nStatus: Mencoba mengakses webcam simulasi...")
    time.sleep(2)
    
    print("\n[SIMULASI] Berhasil mengakses feed webcam!")
    print("-----------------------------------")
    print("|          [GAMBAR ACES]          |")
    print("|    (ini hanyalah simulasi teks) |")
    print("|   Selamat datang di dunia siber!|")
    print("-----------------------------------")
    print("\nWebcam simulasi berhasil diakses.")
    print("Penting: Ini hanyalah simulasi. Webcam Anda aman.")

def ransomware_simulation_cli():
    print("\n--- 20. Ransomware Simulation ---")
    print("Mensimulasikan serangan ransomware. TIDAK ADA FILE NYATA YANG AKAN DIENKRIPSI!")
    
    simulated_files = [
        "dokumen_penting.docx",
        "foto_liburan_keluarga.jpg",
        "catatan_rahasia.txt",
        "spreadsheet_keuangan.xlsx",
        "data_proyek.zip"
    ]
    
    print("\n--- Daftar File Simulasi Awal ---")
    for f in simulated_files:
        print(f"  - {f}")
        
    input("\nTekan ENTER untuk memulai simulasi enkripsi...")
    
    print("\n[SIMULASI] Memulai proses enkripsi file...")
    encrypted_count = 0
    for i, f in enumerate(simulated_files):
        time.sleep(0.3) 
        encrypted_name = f"{f}.ENCRYPTED"
        simulated_files[i] = encrypted_name 
        print(f"  {f} -> {encrypted_name} (Simulasi Enkripsi)")
        encrypted_count += 1
        
    print(f"\n[SIMULASI] {encrypted_count} file berhasil dienkripsi!")
    print("\n!!! FILE ANDA TELAH DIENKRIPSI !!!")
    print("Semua dokumen, foto, dan file penting Anda telah dienkripsi.")
    print("Tidak ada cara untuk mengembalikan data Anda tanpa kunci dekripsi unik.")
    print("\nUNTUK MENDAPATKAN KEMBALI FILE ANDA, BAYAR sejumlah X Bitcoin ke alamat ini: [Alamat Bitcoin Palsu].")
    print("Anda hanya punya 48 jam. Jika tidak, kunci akan dihapus selamanya.")
    print("Jangan mencoba memulihkan sendiri - data Anda bisa rusak permanen.")
    print("\n[INI ADALAH SIMULASI UNTUK TUJUAN EDUKASI SAJA]")
    print("\nSimulasi serangan ransomware selesai. File Anda aman.")

def custom_exploit_development_sim_cli():
    print("\n--- 21. Custom Exploit Development ---")
    print("Mensimulasikan pengembangan eksploitasi untuk kerentanan tertentu.")
    
    vulnerability_type = input("Jenis kerentanan yang disimulasikan (contoh: Buffer Overflow, SQLi): ") or "Buffer Overflow"
    target_app = input("Aplikasi target yang disimulasikan (contoh: Web Server v1.0): ") or "Aplikasi Dummy v1.0"
    
    print(f"\n[SIMULASI] Menganalisis '{vulnerability_type}' pada '{target_app}'...")
    time.sleep(1)
    print("  - Mengidentifikasi offset...")
    time.sleep(0.5)
    print("  - Membuat shellcode dummy...")
    time.sleep(0.5)
    print("  - Membangun payload eksploitasi simulasi...")
    time.sleep(1.5)
    
    exploit_payload = f"Payload eksploitasi dummy untuk {vulnerability_type} di {target_app} (ukuran: {random.randint(100,500)} byte)"
    
    print(f"\n[HASIL SIMULASI] Eksploitasi dummy berhasil dikembangkan:")
    print(f"  Tipe Kerentanan: {vulnerability_type}")
    print(f"  Aplikasi Target: {target_app}")
    print(f"  Payload Eksploitasi: '{exploit_payload}'")
    print("\nPeringatan: Ini adalah simulasi. Pengembangan eksploitasi nyata sangat kompleks dan berisiko.")

def reverse_shell_sim_cli():
    print("\n--- 22. Reverse Shell ---")
    print("Mensimulasikan koneksi reverse shell dari target ke penyerang.")
    
    attacker_ip = input("Masukkan IP penyerang (contoh: 127.0.0.1): ") or "127.0.0.1"
    attacker_port = input("Masukkan port penyerang (contoh: 4444): ") or "4444"
    
    print(f"\n[SIMULASI] Menunggu koneksi dari target di {attacker_ip}:{attacker_port}...")
    time.sleep(2)
    print("  Target simulasi: 'target_host_1' (IP: 192.168.1.100)")
    time.sleep(1)
    
    print(f"\n[SIMULASI] Koneksi masuk dari 192.168.1.100:12345 (target_host_1)!")
    print("  Selamat datang di shell target simulasi.")
    
    print("\nAnda sekarang berada di shell target simulasi. Ketik 'exit' untuk keluar.")
    while True:
        cmd = input("target_host_1> ")
        if cmd.lower() == 'exit':
            print("[SIMULASI] Koneksi reverse shell ditutup.")
            break
        elif cmd.lower() == 'ls' or cmd.lower() == 'dir':
            print("file1.txt  folder_a/  program.exe  secret_doc.pdf")
        elif cmd.lower() == 'whoami':
            print("simulated_user")
        elif cmd.lower() == 'pwd':
            print("/home/simulated_user")
        else:
            print(f"Perintah '{cmd}' dieksekusi di target simulasi (output dummy).")
    print("Peringatan: Ini adalah simulasi. Reverse shell nyata sangat berbahaya.")

def advanced_keylogger_sim_cli():
    print("\n--- 23. Advanced Keylogger ---")
    print("Mensimulasikan keylogger canggih dengan pengiriman log melalui email.")
    print("(Tidak ada email nyata yang dikirim, dan tidak ada penekanan tombol nyata yang direkam.)")
    
    email_target = input("Masukkan email tujuan log simulasi (contoh: log_receiver@example.com): ") or "log_receiver@example.com"
    
    print("\n[SIMULASI] Keylogger canggih memulai perekaman (dummy input)...")
    simulated_keys = "username: testuser password: securepass123 email: my@email.com secret data typed"
    print(f"  Merekam input simulasi: '{simulated_keys}'")
    time.sleep(2)
    
    print("\n[SIMULASI] Menyimpan log yang direkam...")
    simulated_log_file = "advanced_keylog_sim.txt"
    with open(simulated_log_file, "w") as f:
        f.write(f"--- Log Keylogger Canggih Simulasi ({time.ctime()}) ---\n")
        f.write(simulated_keys + "\n")
    print(f"  Log disimpan secara lokal ke '{simulated_log_file}' (simulasi).")
    time.sleep(1)
    
    print(f"\n[SIMULASI] Mengirim log ke '{email_target}' via server SMTP dummy...")
    time.sleep(2)
    print("  Email log simulasi berhasil 'terkirim'!")
    print("\nPeringatan: Ini adalah simulasi. Keylogger nyata berbahaya dan ilegal.")

def vulnerability_scanner_sim_cli():
    print("\n--- 24. Vulnerability Scanner ---")
    print("Mensimulasikan pemindaian kerentanan pada target (web/jaringan).")
    
    target = input("Masukkan target untuk dipindai (contoh: scan.example.com): ") or "scan.example.com"
    
    print(f"\n[SIMULASI] Memulai pemindaian kerentanan pada {target}...")
    time.sleep(2)
    
    vulnerabilities = [
        {"name": "XSS (Cross-Site Scripting)", "severity": "Medium", "path": "/search?q=<script>"},
        {"name": "SQL Injection", "severity": "High", "path": "/login.php?id=' OR 1=1--"},
        {"name": "Directory Traversal", "severity": "Medium", "path": "/download?file=../../../../etc/passwd"},
        {"name": "Outdated Software (Apache 2.2)", "severity": "Low", "path": "/"},
        {"name": "Open Port 8080", "severity": "Info", "path": "8080/tcp"},
    ]
    
    found_vulns = []
    print("\n[HASIL PEMINDAIAN SIMULASI]:")
    for vuln in vulnerabilities:
        if random.random() > 0.3:
            found_vulns.append(vuln)
            print(f"  [Ditemukan] {vuln['name']} (Severity: {vuln['severity']}) di {target}{vuln['path']}")
            time.sleep(0.3)
    
    if not found_vulns:
        print("  Tidak ada kerentanan signifikan yang ditemukan (simulasi).")
    
    print("\nSimulasi pemindaian kerentanan selesai.")
    print("Peringatan: Ini adalah simulasi. Pemindaian kerentanan nyata memerlukan izin.")

def pentesting_framework_sim_cli():
    print("\n--- 25. Pentesting Framework ---")
    print("Mensimulasikan penggunaan kerangka kerja pengujian penetrasi (misalnya Metasploit).")
    
    print("\n[SIMULASI] Memuat kerangka kerja pengujian penetrasi...")
    time.sleep(1)
    print("  msf > use exploit/multi/handler")
    print("  msf exploit(handler) > set PAYLOAD python/meterpreter/reverse_tcp")
    print("  msf exploit(handler) > set LHOST 127.0.0.1")
    print("  msf exploit(handler) > set LPORT 4444")
    print("  msf exploit(handler) > exploit")
    time.sleep(2)
    
    print("\n[SIMULASI] Menunggu sesi Meterpreter...")
    time.sleep(1)
    
    # Simulate a Meterpreter session
    if random.random() > 0.3:
        print("  meterpreter > sysinfo")
        print("    Computer        : TARGET_VM_SIM")
        print("    OS              : Linux target-os (simulasi)")
        print("    Architecture    : x64")
        print("  meterpreter > shell")
        print("\n  Spawning shell on target (simulasi)...")
        print("  target_vm_sim:~# ")
        print("  [SIMULASI] Sesi Meterpreter dan shell berhasil dibuat.")
        print("  Ketik 'exit' di prompt 'target_vm_sim:~#' untuk mengakhiri simulasi shell.")
        
        while True:
            cmd = input("target_vm_sim:~# ")
            if cmd.lower() == 'exit':
                print("[SIMULASI] Sesi shell target ditutup.")
                break
            elif cmd.lower() == 'cat /etc/passwd':
                print("root:x:0:0:root:/root:/bin/bash\nsimulated_user:x:1000:1000:Sim User:/home/simulated_user:/bin/bash")
            else:
                print(f"  Perintah '{cmd}' dieksekusi di target simulasi (output dummy).")
    else:
        print("  [SIMULASI] Tidak ada sesi yang masuk. Eksploitasi mungkin gagal.")
    
    print("\nSimulasi kerangka kerja pengujian penetrasi selesai.")
    print("Peringatan: Ini adalah simulasi. Pengujian penetrasi nyata memerlukan keahlian tinggi dan izin eksplisit.")

def botnet_development_sim_cli():
    print("\n--- 26. Botnet Development ---")
    print("Mensimulasikan pengembangan jaringan bot untuk menjalankan perintah.")
    print("(Tidak ada bot nyata yang dibuat atau dikendalikan.)")
    
    num_bots = random.randint(5, 15)
    print(f"\n[SIMULASI] Menginisialisasi {num_bots} 'bot' dummy...")
    time.sleep(1)
    
    bots = [{"id": i, "status": "online", "ip": f"10.0.0.{random.randint(1,254)}"} for i in range(1, num_bots + 1)]
    
    print("  Bot berhasil terhubung ke server C2 (Command & Control) simulasi.")
    
    while True:
        cmd_to_send = input("\nMasukkan perintah untuk bot (contoh: 'ping example.com', 'ddos', 'exit'): ")
        if cmd_to_send.lower() == 'exit':
            print("[SIMULASI] Server C2 ditutup. Botnet dinonaktifkan.")
            break
        
        print(f"\n[SIMULASI] Mengirim perintah '{cmd_to_send}' ke semua bot...")
        for bot in bots:
            if random.random() > 0.1:
                print(f"  Bot {bot['id']} ({bot['ip']}): Menerima dan menjalankan '{cmd_to_send}' (simulasi).")
            else:
                print(f"  Bot {bot['id']} ({bot['ip']}): Gagal menjalankan perintah (offline/error simulasi).")
            time.sleep(0.1)
        
        if cmd_to_send.lower() == 'ddos':
            print("\n[SIMULASI] Serangan DDoS diluncurkan (dummy traffic).")
            time.sleep(1)
            print("  Target: dummy-target.com (simulasi)")
            print("  Hasil: Server dummy-target.com menunjukkan peningkatan beban (simulasi).")

    print("\nSimulasi pengembangan botnet selesai.")
    print("Peringatan: Pengembangan dan penggunaan botnet adalah ilegal dan merugikan.")

def advanced_malware_simulation_cli():
    print("\n--- 27. Advanced Malware Simulation ---")
    print("Mensimulasikan perilaku malware canggih yang menguji kemampuan deteksi antivirus.")
    print("(Tidak ada malware nyata yang dieksekusi atau merusak sistem Anda.)")
    
    malware_type = input("Jenis malware simulasi (contoh: Rootkit, Trojan, Spyware): ") or "Trojan"
    
    print(f"\n[SIMULASI] Meluncurkan '{malware_type}'...")
    time.sleep(1)
    
    print("  - [SIMULASI] Mencoba memodifikasi entri registry (dummy)...")
    time.sleep(0.5)
    if random.random() > 0.2:
        print("    Antivirus A: Deteksi! (simulasi)")
    else:
        print("    Antivirus A: Tidak terdeteksi (simulasi bypass)")
    
    print("  - [SIMULASI] Mencoba menyisipkan kode ke proses lain (dummy)...")
    time.sleep(0.5)
    if random.random() > 0.3:
        print("    EDR X: Deteksi! (simulasi)")
    else:
        print("    EDR X: Tidak terdeteksi (simulasi bypass)")
        
    print("  - [SIMULASI] Mengenkripsi file dummy (lokal) dan meminta tebusan (simulasi)...")
    time.sleep(1)
    print("    Windows Defender: Deteksi! (simulasi)")
    
    print("\n[HASIL SIMULASI]:")
    if random.random() > 0.5:
        print(f"  Malware simulasi '{malware_type}' terdeteksi oleh beberapa solusi keamanan.")
    else:
        print(f"  Malware simulasi '{malware_type}' berhasil menghindari beberapa deteksi awal.")
    
    print("\nSimulasi malware canggih selesai. Sistem Anda aman.")
    print("Peringatan: Malware nyata sangat merusak dan berbahaya.")

def advanced_dns_spoofing_cli():
    print("\n--- 28. Advanced DNS Spoofing ---")
    print("Mensimulasikan pembajakan DNS tingkat tinggi dengan skenario multi-domain.")
    
    print("\n[SIMULASI] Mengkonfigurasi server DNS palsu untuk beberapa domain...")
    
    spoof_entries = {
        "bank.example.com": "192.168.1.50",
        "social.example.net": "192.168.1.51",
        "update.os.com": "192.168.1.52"
    }
    
    print("  Entri spoofing yang disimulasikan:")
    for domain, ip in spoof_entries.items():
        print(f"    {domain} -> {ip}")
    time.sleep(1.5)
    
    print("\n[SIMULASI] Memicu pembajakan DNS di jaringan target (misalnya melalui kerentanan router DNS, cache poisoning)...")
    time.sleep(2)
    
    print("\n--- Simulasi Kueri DNS dari Klien Target ---")
    for domain, fake_ip in spoof_entries.items():
        if random.random() > 0.2:
            print(f"  Klien meminta '{domain}' -> Menerima IP palsu: {fake_ip} (Sukses Spoof)")
        else:
            # Simulate fallback to legitimate DNS or detection
            try:
                real_ip = socket.gethostbyname(domain)
                print(f"  Klien meminta '{domain}' -> Menerima IP asli: {real_ip} (Spoof Gagal/Terdeteksi)")
            except socket.gaierror:
                print(f"  Klien meminta '{domain}' -> Tidak dapat me-resolve (Domain tidak ada/error)")
        time.sleep(0.5)
        
    print("\nSimulasi pembajakan DNS tingkat tinggi selesai.")
    print("Penting: Ini adalah simulasi. Serangan DNS spoofing nyata bisa sangat merusak.")

def fileless_malware_sim_cli():
    print("\n--- 29. Fileless Malware ---")
    print("Mensimulasikan malware tanpa file yang berjalan langsung di memori.")
    print("(Tidak ada kode berbahaya nyata yang dimuat ke memori.)")
    
    print("\n[SIMULASI] Serangan dimulai. Memuat payload ke memori...")
    time.sleep(1.5)
    
    techniques = [
        "Injeksi kode ke PowerShell (simulasi)",
        "Memanfaatkan WMI (Windows Management Instrumentation) (simulasi)",
        "Menyisipkan payload ke proses legitimate (simulasi)",
        "Menggunakan script dalam registry (simulasi)"
    ]
    
    executed_techniques = random.sample(techniques, k=random.randint(2, len(techniques)))
    
    print("\n[SIMULASI] Teknik yang dieksekusi dalam memori:")
    for tech in executed_techniques:
        print(f"  - {tech}")
        time.sleep(0.7)
        if random.random() > 0.6:
            print("    [Deteksi]: Oleh solusi keamanan memori (simulasi)")
        else:
            print("    [Tidak Terdeteksi]: Berhasil menghindari deteksi awal (simulasi)")
    
    print("\n[SIMULASI] Malware tanpa file telah menjalankan tugasnya dan menghilang dari memori.")
    print("Peringatan: Malware tanpa file sangat sulit dideteksi oleh antivirus tradisional.")

def automated_osint_tool_sim_cli():
    print("\n--- 30. Automated OSINT Tool ---")
    print("Mensimulasikan pengumpulan informasi otomatis dari sumber terbuka (OSINT).")
    
    target_name = input("Masukkan nama/entitas target untuk OSINT (contoh: John Doe, Perusahaan XYZ): ")
    if not target_name:
        print("Nama target tidak boleh kosong.")
        return
        
    print(f"\n[SIMULASI] Mengumpulkan informasi OSINT untuk '{target_name}'...")
    
    data_sources = [
        "Media Sosial Publik",
        "Pencarian Web/Mesin Pencari",
        "Data Pelanggaran (simulasi)",
        "Informasi Registrasi Domain",
        "Forum Publik & Blog"
    ]
    
    collected_info = {}
    print("\n[SIMULASI] Data yang dikumpulkan:")
    for source in data_sources:
        print(f"  Mencari di {source}...")
        time.sleep(0.8)
        
        if random.random() > 0.3:
            info_points = random.randint(1, 3)
            info_list = []
            for _ in range(info_points):
                if "Media Sosial" in source:
                    info_list.append(f"Profil ditemukan: link_dummy_{random.randint(1,99)}")
                elif "Pencarian Web" in source:
                    info_list.append(f"Artikel/berita relevan: judul_dummy_{random.randint(1,99)}")
                elif "Data Pelanggaran" in source:
                    info_list.append(f"Email ditemukan di pelanggaran: user{random.randint(1,99)}@email.com")
                elif "Registrasi Domain" in source:
                    info_list.append(f"Domain terkait: domain{random.randint(1,99)}.com")
                elif "Forum" in source:
                    info_list.append(f"Postingan relevan: post_id_{random.randint(1,99)}")
            
            collected_info[source] = info_list
            for item in info_list:
                print(f"    - {item}")
        else:
            print("    Tidak ada informasi relevan yang ditemukan (simulasi).")
            
    print("\n--- Ringkasan Laporan OSINT (Simulasi) ---")
    if collected_info:
        for source, items in collected_info.items():
            print(f"\nDari {source}:")
            for item in items:
                print(f"  - {item}")
    else:
        print("Tidak ada informasi yang berhasil dikumpulkan (simulasi).")
        
    print("\nSimulasi alat OSINT otomatis selesai.")
    print("Penting: OSINT nyata melibatkan pengumpulan data yang sah dari sumber publik.")

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def loading():
    print(GREEN + "Memuat sistem", end="")
    for _ in range(3):
        time.sleep(0.5)
        print(GREEN + ".", end="")
    time.sleep(0.5)
    print(RESET)

def banner():
    print(CYAN + r"""
 ██████╗██╗   ██╗██████╗ ███████╗██████╗     ████████╗ ██████╗  ██████╗ ██╗     ███████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██╔════╝
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝       ██║   ██║   ██║██║   ██║██║     ███████╗
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗       ██║   ██║   ██║██║   ██║██║     ╚════██║
╚██████╗   ██║   ██████╔╝███████╗██║  ██║       ██║   ╚██████╔╝╚██████╔╝███████╗███████║
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚══════╝
""" + MAGENTA + BOLD + """
        CYBER SECURITY EDUCATIONAL SIMULATION SUITE
        ------------------------------------------------
        ⚠  FOR LEARNING & DEMONSTRATION PURPOSES ONLY
""" + RESET)

def pause():
    input(YELLOW + "\nTekan ENTER untuk kembali ke menu..." + RESET)
    
def run_feature(func):
    clear_screen()
    banner()
    func()
    pause() 

def menu():
    while True:
        clear_screen()
        banner()

        print(WHITE + """
╔═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗
║                                                                   CYBER TOOLS                                                                 ║
║                                                           Educational / Simulation Suite                                                      ║
║═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════║
║               Tingkat Pemula                  ║               Tingakat Menengah               ║               Tingkat Mahir/Ahli              ║
║═══════════════════════════════════════════════║═══════════════════════════════════════════════║═══════════════════════════════════════════════║
║        1. Keylogger Sederhana                 ║        11. Packet Sniffer                     ║        21. Custom Exploit Development         ║
║        2. Port Scanner                        ║        12. ARP Spoofer                        ║        22. Reverse Shell                      ║
║        3. Password Generator                  ║        13. Subdomain Finder                   ║        23. Advanced Keylogger                 ║
║        4. Brute Force Login (Dummy)           ║        14. SQL Injection Simulator            ║        24. Vulnerability Scanner              ║
║        5. Caesar Cipher Encoder/Decoder       ║        15. DNS Spoofer                        ║        25. Pentesting Framework               ║
║        6. Website Crawler                     ║        16. Steganography Tool                 ║        26. Botnet Development                 ║
║        7. MAC Address Changer (Dummy)         ║        17. Network Scanner                    ║        27. Advanced Malware Simulation        ║
║        8. Ping Tester                         ║        18. Email Bomber                       ║        28. Advanced DNS Spoofing              ║
║        9. IP Address Locator                  ║        19. Webcam Hacking Simulator           ║        29. Fileless Malware                   ║
║        10. Screenshot Taker                   ║        20. Ransomware Simulation              ║        30. Automated OSINT Tool               ║
║═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════║
║                                                           0. Keluar dari Program                                                              ║
╚═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝
        """ + RESET)
        
        choice = input(YELLOW + "Pilih menu ➜ " + RESET)
        print("-" * 30)

        if choice == "1":
            run_feature(keylogger)
        elif choice == "2":
            run_feature(port_scanner)
        elif choice == "3":
            run_feature(password_generator)
        elif choice == "4":
            run_feature(brute_force_dummy)
        elif choice == "5":
            run_feature(caesar_cipher)
        elif choice == "6":
            run_feature(website_crawler)
        elif choice == "7":
            run_feature(mac_changer_dummy)
        elif choice == "8":
            run_feature(ping_tester)
        elif choice == "9":
            run_feature(ip_locator)
        elif choice == "10":
            run_feature(screenshot_taker)
        elif choice == "11":
            run_feature(packet_sniffer_sim_cli)
        elif choice == "12":
            run_feature(arp_spoofer_sim_cli)
        elif choice == "13":
            run_feature(subdomain_finder_sim_cli)
        elif choice == "14":
            run_feature(sql_injection_simulator_cli)
        elif choice == "15":
            run_feature(dns_spoofer_sim_cli)
        elif choice == "16":
            run_feature(steganography_tool_sim_cli)
        elif choice == "17":
            run_feature(network_scanner_sim_cli)
        elif choice == "18":
            run_feature(email_bomber_sim_cli)
        elif choice == "19":
            run_feature(webcam_hacking_simulator_cli)
        elif choice == "20":
            run_feature(ransomware_simulation_cli)
        elif choice == "21":
            run_feature(custom_exploit_development_sim_cli)
        elif choice == "22":
            run_feature(reverse_shell_sim_cli)
        elif choice == "23":
            run_feature(advanced_keylogger_sim_cli)
        elif choice == "24":
            run_feature(vulnerability_scanner_sim_cli)
        elif choice == "25":
            run_feature(pentesting_framework_sim_cli)
        elif choice == "26":
            run_feature(botnet_development_sim_cli)
        elif choice == "27":
            run_feature(advanced_malware_simulation_cli)
        elif choice == "28":
            run_feature(advanced_dns_spoofing_cli)
        elif choice == "29":
            run_feature(fileless_malware_sim_cli)
        elif choice == "30":
            run_feature(automated_osint_tool_sim_cli)
        elif choice == "0":
            print(GREEN + "Terima kasih telah menggunakan CYBER TOOLS. Sampai jumpa!" + RESET)
            break

        else:
            print(RED + "Pilihan tidak valid. Silakan coba lagi." + RESET)
            pause()

if __name__ == "__main__":
    clear_screen()
    loading()
    time.sleep(0.3)
    menu()