import socket
import threading
import pyaudio
import time
import math
import base64
import os
import struct
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, simpledialog
from io import BytesIO
from PIL import Image, ImageTk
import noisereduce as nr
import numpy as np
# Pillow kütüphanesi (resim görüntüleme için)
try:
    from PIL import Image, ImageTk
except ImportError:
    messagebox.showerror("Eksik Kütüphane", "Lütfen Pillow kütüphanesini yükleyin:\npip install pillow")
    raise

# noisereduce kütüphanesi (gürültü bastırma için)
try:
    import noisereduce as nr
    import numpy as np
except ImportError:
    messagebox.showerror("Eksik Kütüphane", "Lütfen noisereduce ve numpy kütüphanelerini yükleyin:\npip install noisereduce numpy")
    raise

# Şifreleme için pycryptodome kütüphanesi
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Ses ayarları
CHUNK = 1024
FORMAT = pyaudio.paInt16
CHANNELS = 1
RATE = 44100

# Şifreleme ayarları (16 baytlık anahtar ve IV)
DEFAULT_KEY = b'mysecretpassword'
DEFAULT_IV = b'initialvector123'

def compute_rms(frame):
    count = len(frame) // 2
    if count == 0:
        return 0
    shorts = [int.from_bytes(frame[i*2:(i+1)*2], byteorder='little', signed=True)
              for i in range(count)]
    sum_squares = sum(sample * sample for sample in shorts)
    rms = math.sqrt(sum_squares / count)
    return rms

def adjust_volume(audio_data, multiplier):
    count = len(audio_data) // 2
    samples = struct.unpack('<' + 'h' * count, audio_data)
    new_samples = [max(min(int(sample * multiplier), 32767), -32768) for sample in samples]
    return struct.pack('<' + 'h' * count, *new_samples)

def apply_noise_gate(audio_data, threshold):
    count = len(audio_data) // 2
    samples = list(struct.unpack('<' + 'h' * count, audio_data))
    new_samples = [s if abs(s) >= threshold else 0 for s in samples]
    return struct.pack('<' + 'h' * count, *new_samples)

class PeerToPeerChat:
    def __init__(self, port=5000, input_device=None, output_device=None,
                 username="Kullanıcı", encryption_enabled=True,
                 on_log=None, on_peer_update=None, on_audio_level=None,
                 on_connection_status=None, on_image_received=None, on_file_received=None):
        self.port = port
        self.username = username
        self.encryption_enabled = encryption_enabled
        self.key = DEFAULT_KEY
        self.iv = DEFAULT_IV

        self.on_log = on_log
        self.on_peer_update = on_peer_update
        self.on_audio_level = on_audio_level
        self.on_connection_status = on_connection_status
        self.on_image_received = on_image_received
        self.on_file_received = on_file_received

        self.running = True

        # Ek özellikler: mikrofon/kulaklık susturma, gürültü engelleme ve volume gate ayarı
        self.mic_muted = False
        self.headphone_muted = False
        self.enable_noise_suppression = False
        self.volume_gate = 500
        self.noise_reduction_aggressiveness = 1.5

        self.peer_volumes = {}

        self.public_ip, self.public_port = self.get_public_address()

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.socket.bind(("0.0.0.0", port))
        except Exception as e:
            self.log(f"Soket bağlama hatası: {e}")
            raise

        self.peers = {}
        self.lock = threading.Lock()

        self.ip_address = self.get_ip_address()
        self.log(f"Yerel IP: {self.ip_address}:{self.port} | Public IP: {self.public_ip}:{self.public_port}")

        self.p = pyaudio.PyAudio()
        try:
            self.stream = self.p.open(format=FORMAT, channels=CHANNELS,
                                      rate=RATE, input=True, output=True,
                                      input_device_index=input_device,
                                      output_device_index=output_device,
                                      frames_per_buffer=CHUNK)
        except Exception as e:
            self.log(f"Ses cihazı açılamadı: {e}")
            raise

        self.listen_thread = threading.Thread(target=self.listen, daemon=True)
        self.listen_thread.start()
        self.send_thread = None
        self.heartbeat_thread = threading.Thread(target=self.heartbeat_monitor, daemon=True)
        self.heartbeat_thread.start()

    def log(self, message):
        print(message)
        if self.on_log:
            self.on_log(message)

    def update_peers(self):
        if self.on_peer_update:
            with self.lock:
                peers_list = list(self.peers.keys())
                for peer in peers_list:
                    if peer not in self.peer_volumes:
                        self.peer_volumes[peer] = 1.0
            self.on_peer_update(peers_list)

    def get_ip_address(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def get_public_address(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip, self.port
        except Exception:
            return "0.0.0.0", self.port

    def encrypt(self, plaintext: bytes) -> bytes:
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
        return ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext

    def process_audio(self, data):
        # Önce basit noise gate uygula:
        data = apply_noise_gate(data, int(self.volume_gate))
        if self.enable_noise_suppression:
            audio_np = np.frombuffer(data, dtype=np.int16).astype(np.float32)
            # Gürültü azaltma: n_std_thresh_stationary parametresi kullanılarak
            reduced = nr.reduce_noise(y=audio_np, sr=RATE, n_std_thresh_stationary=self.noise_reduction_aggressiveness)
            # NaN değerleri 0'a çeviriyoruz
            reduced = np.nan_to_num(reduced, nan=0.0)
            data = reduced.astype(np.int16).tobytes()
        return data

    def listen(self):
        self.socket.settimeout(1.0)
        while self.running:
            try:
                data, addr = self.socket.recvfrom(8192)
            except socket.timeout:
                continue
            except Exception as e:
                self.log("Dinleme hatası: " + str(e))
                break

            if data.startswith(b"MSG:"):
                payload = data[4:]
                if self.encryption_enabled and payload.startswith(b"ENC:"):
                    try:
                        decrypted = self.decrypt(payload[4:])
                        text = decrypted.decode()
                    except Exception as e:
                        text = "<şifre çözme hatası>"
                else:
                    try:
                        text = payload.decode()
                    except UnicodeDecodeError:
                        text = "<kod çözülemedi>"
                self.log(f"{addr} - {text}")
            elif data.startswith(b"PRIVATE:"):
                try:
                    parts = data.split(b":", 2)
                    sender = parts[1].decode()
                    payload = parts[2]
                    if self.encryption_enabled and payload.startswith(b"ENC:"):
                        try:
                            decrypted = self.decrypt(payload[4:])
                            text = decrypted.decode()
                        except Exception:
                            text = "<şifre çözme hatası>"
                    else:
                        text = payload.decode()
                    self.log(f"(Özel) {addr} ({sender}): {text}")
                except Exception as e:
                    self.log(f"Özel mesaj ayrıştırma hatası: {e}")
            elif data.startswith(b"IMG:"):
                try:
                    b64data = data[4:]
                    img_data = base64.b64decode(b64data)
                    self.log(f"{addr} tarafından resim gönderildi.")
                    if self.on_image_received:
                        self.on_image_received(img_data)
                except Exception as e:
                    self.log(f"Resim mesajı hata: {e}")
            elif data.startswith(b"FILE:"):
                try:
                    parts = data.split(b":", 2)
                    filename = parts[1].decode()
                    b64data = parts[2]
                    file_data = base64.b64decode(b64data)
                    self.log(f"{addr} tarafından '{filename}' dosyası gönderildi.")
                    if self.on_file_received:
                        self.on_file_received(filename, file_data)
                except Exception as e:
                    self.log(f"Dosya mesajı hata: {e}")
            elif data == b"PING":
                self.socket.sendto(b"PONG", addr)
            elif data == b"PONG":
                with self.lock:
                    if addr in self.peers:
                        self.peers[addr]["last_response"] = time.time()
                    else:
                        self.peers[addr] = {"last_response": time.time(), "username": None}
                self.update_peers()
            elif data == b"HEARTBEAT":
                self.socket.sendto(b"HEARTBEAT_ACK", addr)
            elif data == b"HEARTBEAT_ACK":
                with self.lock:
                    if addr in self.peers:
                        self.peers[addr]["last_response"] = time.time()
            else:
                try:
                    processed_data = self.process_audio(data)
                    multiplier = self.peer_volumes.get(addr, 1.0)
                    processed_data = adjust_volume(processed_data, multiplier)
                    if not self.headphone_muted:
                        self.stream.write(processed_data)
                except Exception as e:
                    self.log("Ses oynatma hatası: " + str(e))
        self.log("Dinleme iş parçacığı sonlandırıldı.")

    def send_audio(self):
        while self.running:
            try:
                if self.mic_muted:
                    data = b'\x00' * CHUNK * 2
                    time.sleep(CHUNK / RATE)
                else:
                    data = self.stream.read(CHUNK)
            except Exception as e:
                self.log("Ses kaydı hatası: " + str(e))
                break

            rms = compute_rms(data)
            if self.on_audio_level:
                self.on_audio_level(rms)

            if rms < self.volume_gate:
                data = b'\x00' * len(data)

            processed_data = self.process_audio(data)
            with self.lock:
                peers = list(self.peers.keys())
            for peer in peers:
                try:
                    self.socket.sendto(processed_data, peer)
                except Exception as e:
                    self.log(f"{peer} adresine ses gönderilemedi: {e}")
        self.log("Ses gönderme iş parçacığı sonlandırıldı.")

    def start_audio(self):
        self.send_thread = threading.Thread(target=self.send_audio, daemon=True)
        self.send_thread.start()

    def send_message(self, message, private_peer=None):
        full_message = f"{self.username}: {message}"
        payload = full_message.encode()
        if self.encryption_enabled:
            enc_payload = b"ENC:" + self.encrypt(payload)
        else:
            enc_payload = payload

        if private_peer:
            data = b"PRIVATE:" + private_peer.encode() + b":" + enc_payload
            try:
                self.socket.sendto(data, private_peer)
            except Exception as e:
                self.log(f"{private_peer} adresine özel mesaj gönderilemedi: {e}")
        else:
            data = b"MSG:" + enc_payload
            with self.lock:
                peers = list(self.peers.keys())
            for peer in peers:
                try:
                    self.socket.sendto(data, peer)
                except Exception as e:
                    self.log(f"{peer} adresine mesaj gönderilemedi: {e}")
        self.log(f"Mesaj gönderildi: {full_message}")

    def send_image(self, file_path):
        try:
            with open(file_path, "rb") as f:
                img_bytes = f.read()
            b64data = base64.b64encode(img_bytes)
            data = b"IMG:" + b64data
            with self.lock:
                peers = list(self.peers.keys())
            for peer in peers:
                self.socket.sendto(data, peer)
            self.log(f"Resim gönderildi: {os.path.basename(file_path)}")
        except Exception as e:
            self.log(f"Resim gönderme hatası: {e}")

    def send_file(self, file_path):
        try:
            with open(file_path, "rb") as f:
                file_bytes = f.read()
            b64data = base64.b64encode(file_bytes)
            filename = os.path.basename(file_path)
            data = b"FILE:" + filename.encode() + b":" + b64data
            with self.lock:
                peers = list(self.peers.keys())
            for peer in peers:
                self.socket.sendto(data, peer)
            self.log(f"Dosya gönderildi: {filename}")
        except Exception as e:
            self.log(f"Dosya gönderme hatası: {e}")

    def hole_punching(self, peer_ip, peer_port):
        self.log(f"NAT açma işlemi başlatılıyor {peer_ip}:{peer_port}")
        target = (peer_ip, peer_port)
        for _ in range(10):
            try:
                self.socket.sendto(b"PING", target)
            except Exception as e:
                self.log(f"Hata: {e}")
            time.sleep(1)
        self.log("Bağlantı kurulmaya çalışılıyor...")
        with self.lock:
            self.peers[target] = {"last_response": time.time(), "username": None}
        self.update_peers()

    def heartbeat_monitor(self):
        while self.running:
            time.sleep(5)
            current = time.time()
            with self.lock:
                remove_list = []
                for peer, info in self.peers.items():
                    if current - info.get("last_response", 0) > 10:
                        remove_list.append(peer)
                for peer in remove_list:
                    self.log(f"Bağlantı zaman aşımına uğradı, {peer} listeden kaldırılıyor.")
                    del self.peers[peer]
            self.update_peers()
            with self.lock:
                for peer in self.peers.keys():
                    try:
                        self.socket.sendto(b"HEARTBEAT", peer)
                    except Exception as e:
                        self.log(f"Heartbeat gönderilemedi {peer}: {e}")
            if self.on_connection_status:
                status = "Bağlantı var" if len(self.peers) > 0 else "Bağlantı yok"
                self.on_connection_status(status)

    def disconnect(self):
        self.running = False
        try:
            self.socket.close()
        except Exception:
            pass
        try:
            self.stream.stop_stream()
            self.stream.close()
        except Exception:
            pass
        self.p.terminate()
        self.log("Bağlantı sonlandırıldı.")


class PeerToPeerChatGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Peer-to-Peer Ses & Mesajlaşma")
        self.set_modern_theme()
        self.create_menu()

        self.pa = pyaudio.PyAudio()
        self.input_devices = self.get_devices(is_input=True)
        self.output_devices = self.get_devices(is_input=False)

        self.create_widgets()
        self.chat = None
        self.attachment_callbacks = {}

    def set_modern_theme(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
            style.configure(".", font=("Segoe UI", 10))
            style.configure("TLabel", background="#ECECEC")
            style.configure("TFrame", background="#ECECEC")
            style.configure("TLabelframe", background="#ECECEC")
            style.configure("TLabelframe.Label", background="#ECECEC")
        except Exception as e:
            print("Tema ayarlanamadı:", e)

    def create_menu(self):
        menubar = tk.Menu(self.root)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Resim Gönder", command=self.send_image)
        file_menu.add_command(label="Dosya Gönder", command=self.send_file)
        menubar.add_cascade(label="Dosya", menu=file_menu)

        theme_menu = tk.Menu(menubar, tearoff=0)
        theme_menu.add_command(label="Light Tema", command=lambda: self.set_theme("default"))
        theme_menu.add_command(label="Dark Tema", command=lambda: self.set_theme("alt"))
        menubar.add_cascade(label="Tema", menu=theme_menu)
        self.root.config(menu=menubar)

    def set_theme(self, theme_name):
        style = ttk.Style()
        try:
            style.theme_use(theme_name)
        except Exception as e:
            messagebox.showerror("Tema Hatası", str(e))

    def get_devices(self, is_input=True):
        devices = []
        for i in range(self.pa.get_device_count()):
            dev = self.pa.get_device_info_by_index(i)
            if is_input and dev.get('maxInputChannels', 0) > 0:
                devices.append((i, dev.get('name')))
            elif not is_input and dev.get('maxOutputChannels', 0) > 0:
                devices.append((i, dev.get('name')))
        return devices

    def create_widgets(self):
        top_frame = ttk.LabelFrame(self.root, text="Kullanıcı & Cihaz Ayarları")
        top_frame.grid(row=0, column=0, padx=10, pady=5, sticky="ew")
        ttk.Label(top_frame, text="Kullanıcı Adı:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.username_entry = ttk.Entry(top_frame)
        self.username_entry.grid(row=0, column=1, padx=5, pady=5)
        self.username_entry.insert(0, "Kullanıcı")

        ttk.Label(top_frame, text="Giriş Cihazı:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.input_combo = ttk.Combobox(top_frame, values=[f"{idx} - {name}" for idx, name in self.input_devices], state="readonly")
        self.input_combo.grid(row=1, column=1, padx=5, pady=5)
        if self.input_devices:
            self.input_combo.current(0)

        ttk.Label(top_frame, text="Çıkış Cihazı:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.output_combo = ttk.Combobox(top_frame, values=[f"{idx} - {name}" for idx, name in self.output_devices], state="readonly")
        self.output_combo.grid(row=2, column=1, padx=5, pady=5)
        if self.output_devices:
            self.output_combo.current(0)

        options_frame = ttk.LabelFrame(self.root, text="Ek Ayarlar")
        options_frame.grid(row=1, column=0, padx=10, pady=5, sticky="ew")
        self.mic_mute_var = tk.BooleanVar()
        self.headphone_mute_var = tk.BooleanVar()
        self.noise_suppression_var = tk.BooleanVar()
        ttk.Checkbutton(options_frame, text="Mikrofonu Sustur", variable=self.mic_mute_var, command=self.toggle_mic_mute).grid(row=0, column=0, padx=5, pady=5)
        ttk.Checkbutton(options_frame, text="Kulaklığı Sustur", variable=self.headphone_mute_var, command=self.toggle_headphone_mute).grid(row=0, column=1, padx=5, pady=5)
        ttk.Checkbutton(options_frame, text="Gürültü Engelleme", variable=self.noise_suppression_var, command=self.toggle_noise_suppression).grid(row=0, column=2, padx=5, pady=5)
        ttk.Label(options_frame, text="Volume Gate (RMS):").grid(row=1, column=0, padx=5, pady=5)
        self.volume_gate_scale = ttk.Scale(options_frame, from_=0, to=2000, orient="horizontal", command=self.change_volume_gate)
        self.volume_gate_scale.set(500)
        self.volume_gate_scale.grid(row=1, column=1, padx=5, pady=5)
        ttk.Label(options_frame, text="Noise Reduction Aggressiveness:").grid(row=1, column=2, padx=5, pady=5)
        self.noise_aggr_scale = ttk.Scale(options_frame, from_=0.5, to=5.0, orient="horizontal", command=self.change_noise_aggressiveness)
        self.noise_aggr_scale.set(1.5)
        self.noise_aggr_scale.grid(row=1, column=3, padx=5, pady=5)

        connection_frame = ttk.LabelFrame(self.root, text="Bağlantı Ayarları")
        connection_frame.grid(row=2, column=0, padx=10, pady=5, sticky="ew")
        ttk.Label(connection_frame, text="Dinleme Portu:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.port_entry = ttk.Entry(connection_frame)
        self.port_entry.grid(row=0, column=1, padx=5, pady=5)
        self.port_entry.insert(0, "5000")
        self.start_button = ttk.Button(connection_frame, text="Sohbete Başla", command=self.start_chat)
        self.start_button.grid(row=0, column=2, padx=5, pady=5)
        ttk.Label(connection_frame, text="Bağlanılacak IP:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.peer_ip_entry = ttk.Entry(connection_frame)
        self.peer_ip_entry.grid(row=1, column=1, padx=5, pady=5)
        ttk.Label(connection_frame, text="Port:").grid(row=1, column=2, sticky="w", padx=5, pady=5)
        self.peer_port_entry = ttk.Entry(connection_frame, width=6)
        self.peer_port_entry.grid(row=1, column=3, padx=5, pady=5)
        self.connect_peer_button = ttk.Button(connection_frame, text="Bağlan", command=self.connect_peer)
        self.connect_peer_button.grid(row=1, column=4, padx=5, pady=5)
        self.disconnect_button = ttk.Button(connection_frame, text="Bağlantıyı Sonlandır", command=self.disconnect_chat, state="disabled")
        self.disconnect_button.grid(row=0, column=4, padx=5, pady=5)

        local_info_frame = ttk.LabelFrame(self.root, text="Yerel Bilgiler")
        local_info_frame.grid(row=3, column=0, padx=10, pady=5, sticky="ew")
        self.local_info_label = ttk.Label(local_info_frame, text="Sohbet başlatılmadan bilgi yok")
        self.local_info_label.pack(padx=5, pady=5)
        self.connection_status_label = ttk.Label(local_info_frame, text="Bağlantı Durumu: -")
        self.connection_status_label.pack(padx=5, pady=5)

        peers_frame = ttk.LabelFrame(self.root, text="Bağlı Katılımcılar")
        peers_frame.grid(row=4, column=0, padx=10, pady=5, sticky="ew")
        self.peers_listbox = tk.Listbox(peers_frame, height=5)
        self.peers_listbox.pack(fill="both", padx=5, pady=5)
        self.peers_listbox.bind("<Button-3>", self.on_peer_right_click)

        vu_frame = ttk.LabelFrame(self.root, text="Mikrofon Seviyesi")
        vu_frame.grid(row=5, column=0, padx=10, pady=5, sticky="ew")
        self.vu_progress = ttk.Progressbar(vu_frame, orient="horizontal", mode="determinate", maximum=100)
        self.vu_progress.pack(fill="x", padx=5, pady=5)

        chat_frame = ttk.LabelFrame(self.root, text="Mesajlar")
        chat_frame.grid(row=6, column=0, padx=10, pady=5, sticky="nsew")
        self.root.grid_rowconfigure(6, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        self.chat_log = scrolledtext.ScrolledText(chat_frame, state="disabled", height=10)
        self.chat_log.pack(fill="both", padx=5, pady=5)
        self.chat_log.tag_config("attachment", foreground="blue", underline=1)
        self.chat_log.tag_bind("attachment", "<Button-1>", self.on_attachment_click)

        message_frame = ttk.Frame(self.root)
        message_frame.grid(row=7, column=0, padx=10, pady=5, sticky="ew")
        self.private_var = tk.BooleanVar()
        self.private_check = ttk.Checkbutton(message_frame, text="Özel Mesaj", variable=self.private_var)
        self.private_check.pack(side="left", padx=5)
        self.message_entry = ttk.Entry(message_frame)
        self.message_entry.pack(side="left", fill="x", expand=True, padx=5)
        self.send_button = ttk.Button(message_frame, text="Gönder", command=self.send_message, state="disabled")
        self.send_button.pack(side="left", padx=5)

    def change_volume_gate(self, val):
        if hasattr(self, "chat") and self.chat is not None:
            self.chat.volume_gate = float(val)
        self.append_log(f"Volume Gate ayarı: {val}")

    def change_noise_aggressiveness(self, val):
        if hasattr(self, "chat") and self.chat is not None:
            self.chat.noise_reduction_aggressiveness = float(val)
        self.append_log(f"Noise Reduction Aggressiveness: {val}")

    def on_peer_right_click(self, event):
        try:
            index = self.peers_listbox.nearest(event.y)
            peer = self.peers_listbox.get(index)
        except Exception:
            return
        ip, port = peer.split(":")
        current_volume = self.chat.peer_volumes.get((ip, int(port)), 1.0)
        new_vol = simpledialog.askfloat("Ses Seviyesi Ayarı", f"{peer} için ses seviyesini ayarlayın (0.0 - 2.0):", initialvalue=current_volume, minvalue=0.0, maxvalue=2.0)
        if new_vol is not None:
            self.chat.peer_volumes[(ip, int(port))] = new_vol
            self.append_log(f"{peer} için ses seviyesi {new_vol*100:.0f}% olarak ayarlandı.")

    def on_attachment_click(self, event):
        index = self.chat_log.index(f"@{event.x},{event.y}")
        tags = self.chat_log.tag_names(index)
        for tag in tags:
            if tag.startswith("attachment_"):
                callback = self.attachment_callbacks.get(tag)
                if callback:
                    callback()
                break

    def add_attachment_log(self, text, callback):
        tag_name = f"attachment_{len(self.attachment_callbacks)}"
        self.attachment_callbacks[tag_name] = callback
        self.chat_log.configure(state="normal")
        self.chat_log.insert(tk.END, text, (tag_name, "attachment"))
        self.chat_log.insert(tk.END, "\n")
        self.chat_log.configure(state="disabled")

    def toggle_mic_mute(self):
        if self.chat:
            self.chat.mic_muted = self.mic_mute_var.get()
            self.append_log("Mikrofon " + ("kapalı" if self.chat.mic_muted else "açık") + " durumda.")

    def toggle_headphone_mute(self):
        if self.chat:
            self.chat.headphone_muted = self.headphone_mute_var.get()  # düzeltilmiş
            self.append_log("Kulaklık " + ("kapalı" if self.chat.headphone_muted else "açık") + " durumda.")

    def toggle_noise_suppression(self):
        if self.chat:
            self.chat.enable_noise_suppression = self.noise_suppression_var.get()
            self.append_log("Gürültü engelleme " + ("aktif" if self.chat.enable_noise_suppression else "pasif") + " durumda.")

    def start_chat(self):
        try:
            port = int(self.port_entry.get())
        except ValueError:
            messagebox.showerror("Hata", "Port numarası geçerli bir sayı olmalıdır.")
            return

        if not self.input_combo.get() or not self.output_combo.get():
            messagebox.showerror("Hata", "Lütfen giriş ve çıkış cihazlarını seçin.")
            return

        username = self.username_entry.get().strip() or "Kullanıcı"
        input_index = int(self.input_combo.get().split(" - ")[0])
        output_index = int(self.output_combo.get().split(" - ")[0])
        try:
            self.chat = PeerToPeerChat(port=port, input_device=input_index, output_device=output_index,
                                         username=username,
                                         on_log=self.append_log, on_peer_update=self.update_peers_list,
                                         on_audio_level=self.update_vu_meter,
                                         on_connection_status=self.update_connection_status,
                                         on_image_received=self.display_image,
                                         on_file_received=self.receive_file)
        except Exception as e:
            messagebox.showerror("Hata", f"Chat başlatılamadı: {e}")
            return

        self.chat.start_audio()
        self.append_log("Sohbet başlatıldı.")
        self.local_info_label.config(text=f"Kendi Adresiniz: {self.chat.ip_address}:{self.chat.port} | Public: {self.chat.public_ip}:{self.chat.public_port}")
        self.start_button.config(state="disabled")
        self.disconnect_button.config(state="normal")
        self.send_button.config(state="normal")

    def connect_peer(self):
        if not self.chat:
            messagebox.showerror("Hata", "Önce sohbeti başlatmalısınız.")
            return
        peer_ip = self.peer_ip_entry.get().strip()
        try:
            peer_port = int(self.peer_port_entry.get().strip())
        except ValueError:
            messagebox.showerror("Hata", "Geçerli bir port numarası girin.")
            return
        threading.Thread(target=self.chat.hole_punching, args=(peer_ip, peer_port), daemon=True).start()

    def disconnect_chat(self):
        if self.chat:
            self.chat.disconnect()
            self.chat = None
            self.append_log("Sohbet sonlandırıldı.")
            self.start_button.config(state="normal")
            self.disconnect_button.config(state="disabled")
            self.send_button.config(state="disabled")
            self.peers_listbox.delete(0, tk.END)
            self.local_info_label.config(text="Sohbet başlatılmadan bilgi yok")
            self.connection_status_label.config(text="Bağlantı Durumu: -")
            self.vu_progress["value"] = 0

    def send_message(self):
        if self.chat:
            message = self.message_entry.get().strip()
            if message:
                if self.private_var.get():
                    try:
                        selected = self.peers_listbox.get(self.peers_listbox.curselection())
                    except Exception:
                        messagebox.showerror("Hata", "Özel mesaj göndermek için lütfen bir peer seçin.")
                        return
                    self.chat.send_message(message, private_peer=selected)
                else:
                    self.chat.send_message(message)
                self.message_entry.delete(0, tk.END)

    def send_image(self):
        if not self.chat:
            messagebox.showerror("Hata", "Önce sohbeti başlatmalısınız.")
            return
        file_path = filedialog.askopenfilename(title="Resim Seç", filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.gif")])
        if file_path:
            self.chat.send_image(file_path)
            self.add_attachment_log(f"[Resim: {os.path.basename(file_path)}] (Tıklayın)", lambda: self.display_image_from_file(file_path))

    def send_file(self):
        if not self.chat:
            messagebox.showerror("Hata", "Önce sohbeti başlatmalısınız.")
            return
        file_path = filedialog.askopenfilename(title="Dosya Seç")
        if file_path:
            self.chat.send_file(file_path)
            self.add_attachment_log(f"[Dosya: {os.path.basename(file_path)}] (Tıklayın)", lambda: self.save_file_from_path(file_path))

    def display_image(self, img_data):
        try:
            image = Image.open(BytesIO(img_data))
            image.thumbnail((400, 400))
            win = tk.Toplevel(self.root)
            win.title("Gelen Resim")
            tk_img = ImageTk.PhotoImage(image)
            lbl = ttk.Label(win, image=tk_img)
            lbl.image = tk_img
            lbl.pack()
            save_button = ttk.Button(win, text="Kaydet", command=lambda: self.save_received_image(img_data))
            save_button.pack(pady=5)
        except Exception as e:
            self.append_log(f"Resim görüntüleme hatası: {e}")

    def display_image_from_file(self, file_path):
        try:
            image = Image.open(file_path)
            image.thumbnail((400, 400))
            win = tk.Toplevel(self.root)
            win.title("Gönderilen Resim")
            tk_img = ImageTk.PhotoImage(image)
            lbl = ttk.Label(win, image=tk_img)
            lbl.image = tk_img
            lbl.pack()
            save_button = ttk.Button(win, text="Kaydet", command=lambda: self.save_file_from_path(file_path))
            save_button.pack(pady=5)
        except Exception as e:
            self.append_log(f"Resim açma hatası: {e}")

    def save_received_image(self, img_data):
        save_path = filedialog.asksaveasfilename(title="Gelen Resmi Kaydet", defaultextension=".png", filetypes=[("PNG", "*.png"), ("JPEG", "*.jpg;*.jpeg")])
        if save_path:
            try:
                with open(save_path, "wb") as f:
                    f.write(img_data)
                self.append_log(f"Resim kaydedildi: {save_path}")
            except Exception as e:
                self.append_log(f"Resim kaydetme hatası: {e}")

    def save_file_from_path(self, file_path):
        save_path = filedialog.asksaveasfilename(initialfile=os.path.basename(file_path), title="Dosyayı Kaydet")
        if save_path:
            try:
                with open(file_path, "rb") as src, open(save_path, "wb") as dst:
                    dst.write(src.read())
                self.append_log(f"Dosya kaydedildi: {save_path}")
            except Exception as e:
                self.append_log(f"Dosya kaydetme hatası: {e}")

    def save_file_from_data(self, filename, file_data):
        save_path = filedialog.asksaveasfilename(initialfile=filename, title="Gelen Dosyayı Kaydet")
        if save_path and file_data:
            try:
                with open(save_path, "wb") as f:
                    f.write(file_data)
                self.append_log(f"Dosya kaydedildi: {save_path}")
            except Exception as e:
                self.append_log(f"Dosya kaydetme hatası: {e}")

    def receive_file(self, filename, file_data):
        def save_callback():
            self.save_file_from_data(filename, file_data)
        self.add_attachment_log(f"[Dosya: {filename}] (Tıklayın)", save_callback)

    def append_log(self, message):
        def inner():
            self.chat_log.configure(state="normal")
            self.chat_log.insert(tk.END, message + "\n")
            self.chat_log.see(tk.END)
            self.chat_log.configure(state="disabled")
        self.root.after(0, inner)

    def update_peers_list(self, peers):
        def inner():
            self.peers_listbox.delete(0, tk.END)
            for peer in peers:
                self.peers_listbox.insert(tk.END, f"{peer[0]}:{peer[1]}")
        self.root.after(0, inner)

    def update_vu_meter(self, rms):
        level = min(int(rms / 300 * 100), 100)
        def inner():
            self.vu_progress["value"] = level
        self.root.after(0, inner)

    def update_connection_status(self, status):
        def inner():
            self.connection_status_label.config(text=f"Bağlantı Durumu: {status}")
        self.root.after(0, inner)

    def on_close(self):
        if self.chat:
            self.chat.disconnect()
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = PeerToPeerChatGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()
