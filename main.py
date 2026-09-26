# -*- coding: utf-8 -*-
import asyncio
import subprocess
import os
import zipfile
import tempfile
import shutil
import time
from datetime import datetime, timedelta
import psutil
import sqlite3
import json
import logging
import signal
import threading
import re
import sys
import atexit
import requests
import hashlib
import mimetypes
import struct

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, InputFile
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, filters, ContextTypes

# --- Flask Keep Alive ---
from flask import Flask
from threading import Thread

app = Flask('')

@app.route('/')
def home():
    return "bot is running...."

def run_flask():
    port = int(os.environ.get("PORT", 8080))
    app.run(host='0.0.0.0', port=port)

def keep_alive():
    t = Thread(target=run_flask)
    t.daemon = True
    t.start()
    print("Flask Keep-Alive server started.")
# --- End Flask Keep Alive ---

# --- Configuration ---
TOKEN = '8653377116:AAGOlJ5FP_3ki_kWAJJG1_t0OoeoYwk0kKY' 
OWNER_ID = 8659378243
ADMIN_ID = 8659378243
YOUR_USERNAME = '@lexivx' 
UPDATE_CHANNEL = '@lexivs'
MENU_VIDEO = 'YOUR_VIDEO_URL_OR_FILE_ID' # Replace with a valid video URL or file_id

# Folder setup - using absolute paths
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_BOTS_DIR = os.path.join(BASE_DIR, 'upload_bots')
IROTECH_DIR = os.path.join(BASE_DIR, 'inf')
DATABASE_PATH = os.path.join(IROTECH_DIR, 'bot_data.db')

# File upload limits
FREE_USER_LIMIT = 10
SUBSCRIBED_USER_LIMIT = 15
ADMIN_LIMIT = 999
OWNER_LIMIT = float('inf')

# Create necessary directories
os.makedirs(UPLOAD_BOTS_DIR, exist_ok=True)
os.makedirs(IROTECH_DIR, exist_ok=True)

# --- Data structures ---
bot_scripts = {}
user_subscriptions = {}
user_files = {}
active_users = set()
admin_ids = {ADMIN_ID, OWNER_ID}
bot_locked = False
user_steps = {} # Replaces register_next_step_handler from telebot

# --- Malware Detection Configuration ---
MALWARE_SIGNATURES = [
    b'MZ', b'\x7fELF', b'\xfe\xed\xfa', b'\xce\xfa\xed\xfe', b'PK', b'Rar!'
]

ENCRYPTED_FILE_INDICATORS = [
    b'openssl', b'encrypted', b'cipher', b'AES', b'DES', b'RSA', b'GPG', b'PGP'
]

SUSPICIOUS_KEYWORDS = [
    b'ransomware', b'trojan', b'virus', b'malware', b'backdoor', b'exploit', 
    b'payload', b'botnet', b'keylogger', b'rootkit'
]

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Universal Color Button Class for PTB ---
# This natively injects the 'style' parameter for Telegram's new colored buttons
class ColorButton(InlineKeyboardButton):
    def __init__(self, text, style=None, **kwargs):
        self._custom_style = style
        super().__init__(text=text, **kwargs)
        
    def to_dict(self):
        d = super().to_dict()
        if self._custom_style:
            d['style'] = self._custom_style
        return d

# --- Database Setup ---
DB_LOCK = threading.Lock() 

def init_db():
    logger.info(f"Initializing database at: {DATABASE_PATH}")
    try:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS subscriptions (user_id INTEGER PRIMARY KEY, expiry TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS user_files (user_id INTEGER, file_name TEXT, file_type TEXT, PRIMARY KEY (user_id, file_name))''')
        c.execute('''CREATE TABLE IF NOT EXISTS active_users (user_id INTEGER PRIMARY KEY)''')
        c.execute('''CREATE TABLE IF NOT EXISTS admins (user_id INTEGER PRIMARY KEY)''')
        c.execute('INSERT OR IGNORE INTO admins (user_id) VALUES (?)', (OWNER_ID,))
        if ADMIN_ID != OWNER_ID:
            c.execute('INSERT OR IGNORE INTO admins (user_id) VALUES (?)', (ADMIN_ID,))
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully.")
    except Exception as e:
        logger.error(f"❌ Database initialization error: {e}", exc_info=True)

def load_data():
    logger.info("Loading data from database...")
    try:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        c = conn.cursor()
        c.execute('SELECT user_id, expiry FROM subscriptions')
        for user_id, expiry in c.fetchall():
            try: user_subscriptions[user_id] = {'expiry': datetime.fromisoformat(expiry)}
            except ValueError: pass
        c.execute('SELECT user_id, file_name, file_type FROM user_files')
        for user_id, file_name, file_type in c.fetchall():
            if user_id not in user_files: user_files[user_id] = []
            user_files[user_id].append((file_name, file_type))
        c.execute('SELECT user_id FROM active_users')
        active_users.update(user_id for (user_id,) in c.fetchall())
        c.execute('SELECT user_id FROM admins')
        admin_ids.update(user_id for (user_id,) in c.fetchall())
        conn.close()
        logger.info(f"Data loaded: {len(active_users)} users, {len(user_subscriptions)} subscriptions, {len(admin_ids)} admins.")
    except Exception as e:
        logger.error(f"❌ Error loading data: {e}", exc_info=True)

init_db()
load_data()

# --- Malware Detection Functions ---
def get_file_type(file_content):
    signatures = { b'\x7fELF': 'application/x-executable', b'MZ': 'application/x-dosexec', b'\xfe\xed\xfa': 'application/x-mach-binary', b'\xce\xfa\xed\xfe': 'application/x-mach-binary', b'PK': 'application/zip', b'Rar!': 'application/x-rar' }
    for sig, mime in signatures.items():
        if file_content.startswith(sig): return mime
    return 'application/octet-stream'

def is_suspicious_file(file_content, file_name):
    file_lower = file_name.lower()
    suspicious_extensions = ['.exe', '.dll', '.bat', '.cmd', '.scr', '.com', '.pif', '.application', '.gadget', '.msi', '.msp', '.com', '.scr', '.hta', '.cpl', '.msc', '.jar', '.bin', '.deb', '.rpm', '.apk', '.app', '.dmg', '.iso', '.img']
    if any(file_lower.endswith(ext) for ext in suspicious_extensions): return True, f"Suspicious file extension: {file_name}"
    for sig in MALWARE_SIGNATURES:
        if file_content.startswith(sig): return True, f"Malware signature detected"
    sample_size = min(len(file_content), 4096)
    file_sample = file_content[:sample_size]
    for ind in ENCRYPTED_FILE_INDICATORS:
        if ind in file_sample: return True, f"Encrypted file indicator"
    sample_text = file_sample.decode('utf-8', errors='ignore').lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw.decode('utf-8').lower() in sample_text: return True, f"Suspicious keyword found"
    try:
        file_type = get_file_type(file_sample)
        if file_type in ['application/x-dosexec', 'application/x-executable', 'application/x-mach-binary']: return True, f"Executable file type"
    except Exception: pass
    return False, "File appears safe"

def scan_file_for_malware(file_content, file_name, user_id):
    if user_id == OWNER_ID: return True, "Owner bypassed security check"
    is_suspicious, reason = is_suspicious_file(file_content, file_name)
    if is_suspicious: return False, f"Security violation: {reason}"
    return True, "File passed security check"

# --- Helper Functions ---
def get_user_folder(user_id):
    user_folder = os.path.join(UPLOAD_BOTS_DIR, str(user_id))
    os.makedirs(user_folder, exist_ok=True)
    return user_folder

def get_user_file_limit(user_id):
    if user_id == OWNER_ID: return OWNER_LIMIT
    if user_id in admin_ids: return ADMIN_LIMIT
    if user_id in user_subscriptions and user_subscriptions[user_id]['expiry'] > datetime.now(): return SUBSCRIBED_USER_LIMIT
    return FREE_USER_LIMIT

def get_user_file_count(user_id):
    return len(user_files.get(user_id, []))

def is_bot_running(script_owner_id, file_name):
    script_key = f"{script_owner_id}_{file_name}"
    script_info = bot_scripts.get(script_key)
    if script_info and script_info.get('process'):
        try:
            proc = psutil.Process(script_info['process'].pid)
            is_running = proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE
            if not is_running:
                if 'log_file' in script_info and not script_info['log_file'].closed:
                    try: script_info['log_file'].close()
                    except: pass
                if script_key in bot_scripts: del bot_scripts[script_key]
            return is_running
        except psutil.NoSuchProcess:
            if 'log_file' in script_info and not script_info['log_file'].closed:
                try: script_info['log_file'].close()
                except: pass
            if script_key in bot_scripts: del bot_scripts[script_key]
            return False
    return False

def kill_process_tree(process_info):
    script_key = process_info.get('script_key', 'N/A')
    try:
        if 'log_file' in process_info and hasattr(process_info['log_file'], 'close') and not process_info['log_file'].closed:
            try: process_info['log_file'].close()
            except: pass
        process = process_info.get('process')
        if process and hasattr(process, 'pid'):
            pid = process.pid
            if pid:
                try:
                    parent = psutil.Process(pid)
                    children = parent.children(recursive=True)
                    for child in children:
                        try: child.terminate()
                        except: pass
                    gone, alive = psutil.wait_procs(children, timeout=1)
                    for p in alive:
                        try: p.kill()
                        except: pass
                    try: parent.terminate(); parent.wait(timeout=1)
                    except psutil.TimeoutExpired: parent.kill()
                except psutil.NoSuchProcess: pass
    except Exception as e: logger.error(f"❌ Error killing {script_key}: {e}")

# --- DB Operation Functions ---
def save_user_file(user_id, file_name, file_type='py'):
    with DB_LOCK:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        c = conn.cursor()
        c.execute('INSERT OR REPLACE INTO user_files (user_id, file_name, file_type) VALUES (?, ?, ?)', (user_id, file_name, file_type))
        conn.commit()
        if user_id not in user_files: user_files[user_id] = []
        user_files[user_id] = [(fn, ft) for fn, ft in user_files[user_id] if fn != file_name]
        user_files[user_id].append((file_name, file_type))
        conn.close()

def remove_user_file_db(user_id, file_name):
    with DB_LOCK:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        c = conn.cursor()
        c.execute('DELETE FROM user_files WHERE user_id = ? AND file_name = ?', (user_id, file_name))
        conn.commit()
        if user_id in user_files:
            user_files[user_id] = [f for f in user_files[user_id] if f[0] != file_name]
            if not user_files[user_id]: del user_files[user_id]
        conn.close()

def add_active_user(user_id):
    active_users.add(user_id) 
    with DB_LOCK:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        c = conn.cursor()
        c.execute('INSERT OR IGNORE INTO active_users (user_id) VALUES (?)', (user_id,))
        conn.commit()
        conn.close()

def save_subscription(user_id, expiry):
    with DB_LOCK:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        c = conn.cursor()
        c.execute('INSERT OR REPLACE INTO subscriptions (user_id, expiry) VALUES (?, ?)', (user_id, expiry.isoformat()))
        conn.commit()
        user_subscriptions[user_id] = {'expiry': expiry}
        conn.close()

def remove_subscription_db(user_id):
    with DB_LOCK:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        c = conn.cursor()
        c.execute('DELETE FROM subscriptions WHERE user_id = ?', (user_id,))
        conn.commit()
        if user_id in user_subscriptions: del user_subscriptions[user_id]
        conn.close()

def add_admin_db(admin_id):
    with DB_LOCK:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        c = conn.cursor()
        c.execute('INSERT OR IGNORE INTO admins (user_id) VALUES (?)', (admin_id,))
        conn.commit()
        admin_ids.add(admin_id) 
        conn.close()

def remove_admin_db(admin_id):
    if admin_id == OWNER_ID: return False 
    with DB_LOCK:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        c = conn.cursor()
        c.execute('SELECT 1 FROM admins WHERE user_id = ?', (admin_id,))
        if c.fetchone():
            c.execute('DELETE FROM admins WHERE user_id = ?', (admin_id,))
            conn.commit()
            removed = c.rowcount > 0 
            if removed: admin_ids.discard(admin_id)
            conn.close()
            return removed
        conn.close()
        return False

# --- Menu Creation ---
def create_main_menu_inline(user_id):
    keyboard = []
    keyboard.append([
        ColorButton('📢 Updates Channel', url=f'https://t.me/{UPDATE_CHANNEL.replace("@", "")}', style='primary'),
        ColorButton('📤 Upload File', callback_data='upload', style='primary')
    ])
    keyboard.append([
        ColorButton('📂 Check Files', callback_data='check_files', style='success'),
        ColorButton('⚡ Bot Speed', callback_data='speed', style='primary')
    ])
    keyboard.append([
        ColorButton('📤 Send Command', callback_data='send_command', style='primary'),
        ColorButton('📞 Contact Owner', url=f'https://t.me/{YOUR_USERNAME.replace("@", "")}', style='primary')
    ])

    if user_id in admin_ids:
        keyboard.append([ColorButton('💳 Subscriptions', callback_data='subscription', style='primary'), ColorButton('📊 Statistics', callback_data='stats', style='primary')])
        keyboard.append([ColorButton('🔒 Lock Bot' if not bot_locked else '🔓 Unlock Bot', callback_data='lock_bot' if not bot_locked else 'unlock_bot', style='danger' if not bot_locked else 'success'), ColorButton('📢 Broadcast', callback_data='broadcast', style='danger')])
        keyboard.append([ColorButton('👑 Admin Panel', callback_data='admin_panel', style='primary'), ColorButton('🏃 Run All Scripts', callback_data='run_all_scripts', style='success')])
    else:
        keyboard.append([ColorButton('📊 Statistics', callback_data='stats', style='primary')])
    return InlineKeyboardMarkup(keyboard)

def create_control_buttons(script_owner_id, file_name, is_running=True):
    keyboard = []
    if is_running:
        keyboard.append([ColorButton("🛑 Stop", callback_data=f'stop_{script_owner_id}_{file_name}', style='danger'), ColorButton("🔄 Restart", callback_data=f'restart_{script_owner_id}_{file_name}', style='primary')])
        keyboard.append([ColorButton("🗑️ Delete", callback_data=f'delete_{script_owner_id}_{file_name}', style='danger'), ColorButton("📜 Logs", callback_data=f'logs_{script_owner_id}_{file_name}', style='primary')])
        keyboard.append([ColorButton("📊 Live Usage", callback_data=f'usage_{script_owner_id}_{file_name}', style='primary')])
    else:
        keyboard.append([ColorButton("▶️ Start", callback_data=f'start_{script_owner_id}_{file_name}', style='success'), ColorButton("🗑️ Delete", callback_data=f'delete_{script_owner_id}_{file_name}', style='danger')])
        keyboard.append([ColorButton("📜 View Logs", callback_data=f'logs_{script_owner_id}_{file_name}', style='primary')])
    keyboard.append([ColorButton("🔙 Back to Files", callback_data='check_files', style='primary')])
    return InlineKeyboardMarkup(keyboard)

def create_admin_panel():
    keyboard = [
        [ColorButton('➕ Add Admin', callback_data='add_admin', style='success'), ColorButton('➖ Remove Admin', callback_data='remove_admin', style='danger')],
        [ColorButton('📋 List Admins', callback_data='list_admins', style='primary')],
        [ColorButton('🔙 Back to Main', callback_data='back_to_main', style='primary')]
    ]
    return InlineKeyboardMarkup(keyboard)

def create_subscription_menu():
    keyboard = [
        [ColorButton('➕ Add Subscription', callback_data='add_subscription', style='success'), ColorButton('➖ Remove Subscription', callback_data='remove_subscription', style='danger')],
        [ColorButton('🔍 Check Subscription', callback_data='check_subscription', style='primary')],
        [ColorButton('🔙 Back to Main', callback_data='back_to_main', style='primary')]
    ]
    return InlineKeyboardMarkup(keyboard)

def create_send_command_menu():
    keyboard = [
        [ColorButton('📝 Send to Process', callback_data='send_to_process', style='success'), ColorButton('🔍 View All Logs', callback_data='view_all_logs', style='primary')],
        [ColorButton('🔙 Back to Main', callback_data='back_to_main', style='primary')]
    ]
    return InlineKeyboardMarkup(keyboard)

# --- Map Telegram import names to actual PyPI package names ---
TELEGRAM_MODULES = {
    'telebot': 'pyTelegramBotAPI', 'telegram': 'python-telegram-bot', 'python_telegram_bot': 'python-telegram-bot',
    'aiogram': 'aiogram', 'pyrogram': 'pyrogram', 'telethon': 'telethon', 'telethon.sync': 'telethon',
    'from telethon.sync import telegramclient': 'telethon', 'telepot': 'telepot', 'pytg': 'pytg',
    'tgcrypto': 'tgcrypto', 'bs4': 'beautifulsoup4', 'requests': 'requests', 'pillow': 'Pillow',
    'cv2': 'opencv-python', 'yaml': 'PyYAML', 'dotenv': 'python-dotenv', 'dateutil': 'python-dateutil',
    'pandas': 'pandas', 'numpy': 'numpy', 'flask': 'Flask', 'django': 'Django', 'sqlalchemy': 'SQLAlchemy',
    'asyncio': None, 'json': None, 'datetime': None, 'os': None, 'sys': None, 're': None, 'time': None,
    'math': None, 'random': None, 'logging': None, 'threading': None, 'subprocess': None, 'zipfile': None,
    'tempfile': None, 'shutil': None, 'sqlite3': None, 'psutil': 'psutil', 'atexit': None
}

# --- Automatic Package Installation & Script Running (Threaded for safety) ---
def sync_send_message(bot, chat_id, text, loop):
    asyncio.run_coroutine_threadsafe(bot.send_message(chat_id=chat_id, text=text, parse_mode='Markdown'), loop)

def attempt_install_pip(module_name, chat_id, bot, loop):
    package_name = TELEGRAM_MODULES.get(module_name.lower(), module_name) 
    if package_name is None: return False 
    try:
        sync_send_message(bot, chat_id, f"🐍 Module `{module_name}` not found. Installing `{package_name}`...", loop)
        command = [sys.executable, '-m', 'pip', 'install', package_name]
        result = subprocess.run(command, capture_output=True, text=True, check=False, encoding='utf-8', errors='ignore')
        if result.returncode == 0:
            sync_send_message(bot, chat_id, f"✅ Package `{package_name}` (for `{module_name}`) installed.", loop)
            return True
        else:
            error_msg = f"❌ Failed to install `{package_name}` for `{module_name}`.\nLog:\n```\n{result.stderr or result.stdout}\n```"
            if len(error_msg) > 4000: error_msg = error_msg[:4000] + "\n... (Log truncated)"
            sync_send_message(bot, chat_id, error_msg, loop)
            return False
    except Exception as e:
        sync_send_message(bot, chat_id, f"❌ Error installing `{package_name}`: {str(e)}", loop)
        return False

def attempt_install_npm(module_name, user_folder, chat_id, bot, loop):
    try:
        sync_send_message(bot, chat_id, f"🟠 Node package `{module_name}` not found. Installing locally...", loop)
        command = ['npm', 'install', module_name]
        result = subprocess.run(command, capture_output=True, text=True, check=False, cwd=user_folder, encoding='utf-8', errors='ignore')
        if result.returncode == 0:
            sync_send_message(bot, chat_id, f"✅ Node package `{module_name}` installed locally.", loop)
            return True
        else:
            error_msg = f"❌ Failed to install Node package `{module_name}`.\nLog:\n```\n{result.stderr or result.stdout}\n```"
            if len(error_msg) > 4000: error_msg = error_msg[:4000] + "\n... (Log truncated)"
            sync_send_message(bot, chat_id, error_msg, loop)
            return False
    except FileNotFoundError:
         sync_send_message(bot, chat_id, "❌ Error: 'npm' not found. Ensure Node.js/npm are installed and in PATH.", loop)
         return False
    except Exception as e:
        sync_send_message(bot, chat_id, f"❌ Error installing Node package `{module_name}`: {str(e)}", loop)
        return False

def run_script(script_path, script_owner_id, user_folder, file_name, chat_id, bot, loop, attempt=1):
    max_attempts = 2 
    if attempt > max_attempts:
        sync_send_message(bot, chat_id, f"❌ Failed to run '{file_name}' after {max_attempts} attempts. Check logs.", loop)
        return

    script_key = f"{script_owner_id}_{file_name}"
    try:
        if not os.path.exists(script_path):
             sync_send_message(bot, chat_id, f"❌ Error: Script '{file_name}' not found at '{script_path}'!", loop)
             remove_user_file_db(script_owner_id, file_name)
             return

        if attempt == 1:
            check_command = [sys.executable, script_path]
            check_proc = None
            try:
                check_proc = subprocess.Popen(check_command, cwd=user_folder, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='ignore')
                stdout, stderr = check_proc.communicate(timeout=5)
                if check_proc.returncode != 0 and stderr:
                    match_py = re.search(r"ModuleNotFoundError: No module named '(.+?)'", stderr)
                    if match_py:
                        module_name = match_py.group(1).strip().strip("'\"")
                        if attempt_install_pip(module_name, chat_id, bot, loop):
                            sync_send_message(bot, chat_id, f"🔄 Install successful. Retrying '{file_name}'...", loop)
                            time.sleep(2)
                            threading.Thread(target=run_script, args=(script_path, script_owner_id, user_folder, file_name, chat_id, bot, loop, attempt + 1)).start()
                            return
                        else:
                            sync_send_message(bot, chat_id, f"❌ Install failed. Cannot run '{file_name}'.", loop)
                            return
                    else:
                         sync_send_message(bot, chat_id, f"❌ Error in script pre-check for '{file_name}':\n```\n{stderr[:500]}\n```", loop)
                         return
            except subprocess.TimeoutExpired:
                if check_proc and check_proc.poll() is None: check_proc.kill(); check_proc.communicate()
            except Exception as e:
                 sync_send_message(bot, chat_id, f"❌ Unexpected error in script pre-check for '{file_name}': {e}", loop)
                 return
            finally:
                 if check_proc and check_proc.poll() is None: check_proc.kill(); check_proc.communicate()

        log_file_path = os.path.join(user_folder, f"{os.path.splitext(file_name)[0]}.log")
        try: log_file = open(log_file_path, 'w', encoding='utf-8', errors='ignore')
        except Exception as e:
             sync_send_message(bot, chat_id, f"❌ Failed to open log file '{log_file_path}': {e}", loop)
             return
        try:
            startupinfo = None; creationflags = 0
            if os.name == 'nt':
                 startupinfo = subprocess.STARTUPINFO(); startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                 startupinfo.wShowWindow = subprocess.SW_HIDE
            process = subprocess.Popen(
                [sys.executable, script_path], cwd=user_folder, stdout=log_file, stderr=log_file,
                stdin=subprocess.PIPE, startupinfo=startupinfo, creationflags=creationflags,
                encoding='utf-8', errors='ignore'
            )
            bot_scripts[script_key] = {
                'process': process, 'log_file': log_file, 'file_name': file_name,
                'chat_id': chat_id, 'script_owner_id': script_owner_id,
                'start_time': datetime.now(), 'user_folder': user_folder, 'type': 'py', 'script_key': script_key
            }
            sync_send_message(bot, chat_id, f"✅ Python script '{file_name}' started! (PID: {process.pid})", loop)
        except Exception as e:
            if log_file and not log_file.closed: log_file.close()
            sync_send_message(bot, chat_id, f"❌ Error starting Python script '{file_name}': {str(e)}", loop)
            if script_key in bot_scripts: del bot_scripts[script_key]
    except Exception as e:
        sync_send_message(bot, chat_id, f"❌ Unexpected error running Python script '{file_name}': {str(e)}", loop)
        if script_key in bot_scripts:
             kill_process_tree(bot_scripts[script_key])
             del bot_scripts[script_key]

def run_js_script(script_path, script_owner_id, user_folder, file_name, chat_id, bot, loop, attempt=1):
    max_attempts = 2
    if attempt > max_attempts:
        sync_send_message(bot, chat_id, f"❌ Failed to run '{file_name}' after {max_attempts} attempts. Check logs.", loop)
        return

    script_key = f"{script_owner_id}_{file_name}"
    try:
        if not os.path.exists(script_path):
             sync_send_message(bot, chat_id, f"❌ Error: Script '{file_name}' not found at '{script_path}'!", loop)
             remove_user_file_db(script_owner_id, file_name)
             return

        if attempt == 1:
            check_command = ['node', script_path]
            check_proc = None
            try:
                check_proc = subprocess.Popen(check_command, cwd=user_folder, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='ignore')
                stdout, stderr = check_proc.communicate(timeout=5)
                if check_proc.returncode != 0 and stderr:
                    match_js = re.search(r"Cannot find module '(.+?)'", stderr)
                    if match_js:
                        module_name = match_js.group(1).strip().strip("'\"")
                        if not module_name.startswith('.') and not module_name.startswith('/'):
                             if attempt_install_npm(module_name, user_folder, chat_id, bot, loop):
                                 sync_send_message(bot, chat_id, f"🔄 NPM Install successful. Retrying '{file_name}'...", loop)
                                 time.sleep(2)
                                 threading.Thread(target=run_js_script, args=(script_path, script_owner_id, user_folder, file_name, chat_id, bot, loop, attempt + 1)).start()
                                 return
                             else:
                                 sync_send_message(bot, chat_id, f"❌ NPM Install failed. Cannot run '{file_name}'.", loop)
                                 return
                    sync_send_message(bot, chat_id, f"❌ Error in JS script pre-check for '{file_name}':\n```\n{stderr[:500]}\n```", loop)
                    return
            except subprocess.TimeoutExpired:
                if check_proc and check_proc.poll() is None: check_proc.kill(); check_proc.communicate()
            except Exception as e:
                 sync_send_message(bot, chat_id, f"❌ Unexpected error in JS pre-check for '{file_name}': {e}", loop)
                 return
            finally:
                 if check_proc and check_proc.poll() is None: check_proc.kill(); check_proc.communicate()

        log_file_path = os.path.join(user_folder, f"{os.path.splitext(file_name)[0]}.log")
        try: log_file = open(log_file_path, 'w', encoding='utf-8', errors='ignore')
        except Exception as e:
            sync_send_message(bot, chat_id, f"❌ Failed to open log file '{log_file_path}': {e}", loop)
            return
        try:
            startupinfo = None; creationflags = 0
            if os.name == 'nt':
                 startupinfo = subprocess.STARTUPINFO(); startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                 startupinfo.wShowWindow = subprocess.SW_HIDE
            process = subprocess.Popen(
                ['node', script_path], cwd=user_folder, stdout=log_file, stderr=log_file,
                stdin=subprocess.PIPE, startupinfo=startupinfo, creationflags=creationflags,
                encoding='utf-8', errors='ignore'
            )
            bot_scripts[script_key] = {
                'process': process, 'log_file': log_file, 'file_name': file_name,
                'chat_id': chat_id, 'script_owner_id': script_owner_id,
                'start_time': datetime.now(), 'user_folder': user_folder, 'type': 'js', 'script_key': script_key
            }
            sync_send_message(bot, chat_id, f"✅ JS script '{file_name}' started! (PID: {process.pid})", loop)
        except Exception as e:
            if log_file and not log_file.closed: log_file.close()
            sync_send_message(bot, chat_id, f"❌ Error starting JS script '{file_name}': {str(e)}", loop)
            if script_key in bot_scripts: del bot_scripts[script_key]
    except Exception as e:
        sync_send_message(bot, chat_id, f"❌ Unexpected error running JS script '{file_name}': {str(e)}", loop)
        if script_key in bot_scripts:
             kill_process_tree(bot_scripts[script_key])
             del bot_scripts[script_key]

# --- Async Command Handlers ---
async def command_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    chat_id = update.effective_chat.id
    user_name = update.effective_user.first_name

    if bot_locked and user_id not in admin_ids:
        await context.bot.send_message(chat_id, "⚠️ Bot locked by admin. Try later.")
        return

    try:
        anim_msg = await context.bot.send_message(chat_id, "⚙️ Loading...")
        await asyncio.sleep(1)
        await context.bot.edit_message_text("⚡ this bot is made by sid..", chat_id=chat_id, message_id=anim_msg.message_id)
        await asyncio.sleep(1.5)
        await context.bot.edit_message_text("✨ this bot is made by sid.. use and enjoy", chat_id=chat_id, message_id=anim_msg.message_id)
        await asyncio.sleep(1.5)
        await context.bot.edit_message_text("🎉 this bot is made by sid.. use and enjoy 🚀", chat_id=chat_id, message_id=anim_msg.message_id)
        await asyncio.sleep(1)
        await context.bot.delete_message(chat_id=chat_id, message_id=anim_msg.message_id)
    except Exception as e:
        logger.error(f"Animation error: {e}")

    user_bio = "Could not fetch bio"; photo_file_id = None
    try: 
        chat_info = await context.bot.get_chat(user_id)
        user_bio = chat_info.bio or "No bio"
    except Exception: pass
    try:
        user_profile_photos = await context.bot.get_user_profile_photos(user_id, limit=1)
        if user_profile_photos.photos: photo_file_id = user_profile_photos.photos[0][-1].file_id
    except Exception: pass

    if user_id not in active_users:
        add_active_user(user_id)
        try:
            owner_notification = (f"🎉 New user!\n👤 Name: {user_name}\n"
                                  f"🆔 ID: `{user_id}`\n📝 Bio: {user_bio}")
            await context.bot.send_message(OWNER_ID, owner_notification, parse_mode='Markdown')
            if photo_file_id: await context.bot.send_photo(OWNER_ID, photo_file_id, caption=f"Pic of new user {user_id}")
        except Exception as e: logger.error(f"⚠️ Failed to notify owner: {e}")

    file_limit = get_user_file_limit(user_id)
    current_files = get_user_file_count(user_id)
    limit_str = str(file_limit) if file_limit != float('inf') else "Unlimited"
    expiry_info = ""
    if user_id == OWNER_ID: user_status = "👑 Owner"
    elif user_id in admin_ids: user_status = "🛡️ Admin"
    elif user_id in user_subscriptions:
        expiry_date = user_subscriptions[user_id].get('expiry')
        if expiry_date and expiry_date > datetime.now():
            user_status = "⭐ Premium"; days_left = (expiry_date - datetime.now()).days
            expiry_info = f"\n⏳ Subscription expires in: {days_left} days"
        else: user_status = "🆓 Free User (Expired Sub)"; remove_subscription_db(user_id)
    else: user_status = "🆓 Free User"

    welcome_msg_text = (f"〽️ Welcome, {user_name}!\n\n🆔 Your User ID: `{user_id}`\n"
                        f"🔰 Your Status: {user_status}{expiry_info}\n📁 Files Uploaded: {current_files} / {limit_str}\n\n"
                        f"🤖 Host & run Python (`.py`) or JS (`.js`) scripts.\n   Upload single scripts or `.zip` archives.\n\n"
                        f"👇 Use buttons or type commands.")
    main_reply_markup = create_main_menu_inline(user_id)
    
    if MENU_VIDEO == 'YOUR_VIDEO_URL_OR_FILE_ID':
         try: await context.bot.send_message(chat_id, text=welcome_msg_text, reply_markup=main_reply_markup, parse_mode='Markdown')
         except Exception as e: logger.error(f"Fallback send failed: {e}")
    else:
         try:
             if photo_file_id: await context.bot.send_photo(chat_id, photo_file_id)
             await context.bot.send_video(chat_id, video=MENU_VIDEO, caption=welcome_msg_text, reply_markup=main_reply_markup, parse_mode='Markdown')
         except Exception as e:
             logger.error(f"Error sending welcome video: {e}")
             await context.bot.send_message(chat_id, text=welcome_msg_text, reply_markup=main_reply_markup, parse_mode='Markdown')

async def command_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    total_users = len(active_users)
    total_files_records = sum(len(files) for files in user_files.values())
    running_bots_count = 0
    user_running_bots = 0

    for script_key_iter, script_info_iter in list(bot_scripts.items()):
        s_owner_id, _ = script_key_iter.split('_', 1)
        if is_bot_running(int(s_owner_id), script_info_iter['file_name']):
            running_bots_count += 1
            if int(s_owner_id) == user_id: user_running_bots +=1

    stats_msg_base = (f"📊 Bot Statistics:\n\n👥 Total Users: {total_users}\n📂 Total File Records: {total_files_records}\n"
                      f"🟢 Total Active Bots: {running_bots_count}\n")

    if user_id in admin_ids:
        stats_msg_admin = (f"🔒 Bot Status: {'🔴 Locked' if bot_locked else '🟢 Unlocked'}\n🤖 Your Running Bots: {user_running_bots}")
        stats_msg = stats_msg_base + stats_msg_admin
    else:
        stats_msg = stats_msg_base + f"🤖 Your Running Bots: {user_running_bots}"
    await update.message.reply_text(stats_msg)

async def command_ping(update: Update, context: ContextTypes.DEFAULT_TYPE):
    start_ping_time = time.time() 
    msg = await update.message.reply_text("Pong!")
    latency = round((time.time() - start_ping_time) * 1000, 2)
    await msg.edit_text(f"Pong! Latency: {latency} ms")

async def command_updates_channel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    markup = InlineKeyboardMarkup([[ColorButton('📢 Updates Channel', url=f'https://t.me/{UPDATE_CHANNEL.replace("@", "")}', style='primary')]])
    await update.message.reply_text("Visit our Updates Channel:", reply_markup=markup)

async def command_upload_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if bot_locked and user_id not in admin_ids:
        await update.message.reply_text("⚠️ Bot locked by admin, cannot accept files.")
        return
    file_limit = get_user_file_limit(user_id)
    if get_user_file_count(user_id) >= file_limit:
        limit_str = str(file_limit) if file_limit != float('inf') else "Unlimited"
        await update.message.reply_text(f"⚠️ File limit ({get_user_file_count(user_id)}/{limit_str}) reached. Delete files first.")
        return
    await update.message.reply_text("📤 Send your Python (`.py`), JS (`.js`), or ZIP (`.zip`) file.")

async def command_check_files(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    user_files_list = user_files.get(user_id, [])
    if not user_files_list:
        await update.message.reply_text("📂 Your files:\n\n(No files uploaded yet)")
        return
    kb = []
    for file_name, file_type in sorted(user_files_list):
        is_running = is_bot_running(user_id, file_name)
        status_icon = "🟢" if is_running else "🔴"
        style = 'success' if is_running else 'danger'
        kb.append([ColorButton(f"{status_icon} {file_name} ({file_type})", callback_data=f'file_{user_id}_{file_name}', style=style)])
    await update.message.reply_text("📂 Your files:\nClick to manage.", reply_markup=InlineKeyboardMarkup(kb), parse_mode='Markdown')

async def command_bot_speed(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    start_time_ping = time.time()
    wait_msg = await update.message.reply_text("🏃 Testing speed...")
    await context.bot.send_chat_action(update.effective_chat.id, 'typing')
    response_time = round((time.time() - start_time_ping) * 1000, 2)
    status = "🔓 Unlocked" if not bot_locked else "🔒 Locked"
    user_level = "🆓 Free User"
    if user_id == OWNER_ID: user_level = "👑 Owner"
    elif user_id in admin_ids: user_level = "🛡️ Admin"
    elif user_id in user_subscriptions and user_subscriptions[user_id].get('expiry', datetime.min) > datetime.now(): user_level = "⭐ Premium"
    speed_msg = f"⚡ Bot Speed & Status:\n\n⏱️ API Response Time: {response_time} ms\n🚦 Bot Status: {status}\n👤 Your Level: {user_level}"
    await wait_msg.edit_text(speed_msg)

async def command_send_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if bot_locked and user_id not in admin_ids:
        await update.message.reply_text("⚠️ Bot locked by admin.")
        return
    await update.message.reply_text("📤 Send Command Options:", reply_markup=create_send_command_menu())

async def command_contact_owner(update: Update, context: ContextTypes.DEFAULT_TYPE):
    markup = InlineKeyboardMarkup([[ColorButton('📞 Contact Owner', url=f'https://t.me/{YOUR_USERNAME.replace("@", "")}', style='primary')]])
    await update.message.reply_text("Click to contact Owner:", reply_markup=markup)

async def command_subscriptions(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id not in admin_ids:
        await update.message.reply_text("⚠️ Admin permissions required.")
        return
    await update.message.reply_text("💳 Subscription Management\nUse inline buttons from /start or admin command menu.", reply_markup=create_subscription_menu())

async def command_statistics(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await command_status(update, context)

async def command_broadcast(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id not in admin_ids:
        await update.message.reply_text("⚠️ Admin permissions required.")
        return
    await update.message.reply_text("📢 Send message to broadcast to all active users.\n/cancel to abort.")
    user_steps[update.effective_user.id] = process_broadcast_message

async def command_lock_bot(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id not in admin_ids:
        await update.message.reply_text("⚠️ Admin permissions required.")
        return
    global bot_locked
    bot_locked = not bot_locked
    status = "locked" if bot_locked else "unlocked"
    logger.warning(f"Bot {status} by Admin {update.effective_user.id} via command/button.")
    await update.message.reply_text(f"🔒 Bot has been {status}.")

async def command_admin_panel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id not in admin_ids:
        await update.message.reply_text("⚠️ Admin permissions required.")
        return
    await update.message.reply_text("👑 Admin Panel\nManage admins. Use inline buttons from /start or admin menu.", reply_markup=create_admin_panel())

async def _logic_run_all_scripts(user_id, chat_id, bot):
    if user_id not in admin_ids:
        await bot.send_message(chat_id, "⚠️ Admin permissions required.")
        return
    await bot.send_message(chat_id, "⏳ Starting process to run all user scripts. This may take a while...")
    started_count = 0; attempted_users = 0; skipped_files = 0; error_files_details = []
    all_user_files_snapshot = dict(user_files)
    loop = asyncio.get_running_loop()

    for target_user_id, files_for_user in all_user_files_snapshot.items():
        if not files_for_user: continue
        attempted_users += 1
        user_folder = get_user_folder(target_user_id)
        for file_name, file_type in files_for_user:
            if not is_bot_running(target_user_id, file_name):
                file_path = os.path.join(user_folder, file_name)
                if os.path.exists(file_path):
                    try:
                        if file_type == 'py': threading.Thread(target=run_script, args=(file_path, target_user_id, user_folder, file_name, chat_id, bot, loop)).start()
                        elif file_type == 'js': threading.Thread(target=run_js_script, args=(file_path, target_user_id, user_folder, file_name, chat_id, bot, loop)).start()
                        started_count += 1
                        await asyncio.sleep(0.7)
                    except Exception as e:
                        error_files_details.append(f"`{file_name}` (User {target_user_id}) - Start error")
                        skipped_files += 1
                else:
                    error_files_details.append(f"`{file_name}` (User {target_user_id}) - File not found")
                    skipped_files += 1

    summary_msg = f"✅ All Users' Scripts - Processing Complete:\n\n▶️ Attempted to start: {started_count} scripts.\n👥 Users processed: {attempted_users}.\n"
    if skipped_files > 0:
        summary_msg += f"⚠️ Skipped/Error files: {skipped_files}\n"
        if error_files_details:
             summary_msg += "Details (first 5):\n" + "\n".join([f"  - {err}" for err in error_files_details[:5]])
             if len(error_files_details) > 5: summary_msg += "\n  ... and more (check logs)."
    await bot.send_message(chat_id, summary_msg, parse_mode='Markdown')

async def command_run_all_code(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await _logic_run_all_scripts(update.effective_user.id, update.effective_chat.id, context.bot)

# --- File Handling (Async adaptation) ---
async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    chat_id = update.effective_chat.id
    doc = update.message.document

    if bot_locked and user_id not in admin_ids:
        await update.message.reply_text("⚠️ Bot locked, cannot accept files.")
        return

    if get_user_file_count(user_id) >= get_user_file_limit(user_id):
        await update.message.reply_text("⚠️ File limit reached. Delete files via menu.")
        return

    file_name = doc.file_name
    if not file_name: 
        await update.message.reply_text("⚠️ No file name."); return
        
    file_ext = os.path.splitext(file_name)[1].lower()
    if file_ext not in ['.py', '.js', '.zip']:
        await update.message.reply_text("⚠️ Unsupported type! Only `.py`, `.js`, `.zip` allowed.")
        return
        
    if doc.file_size > 20 * 1024 * 1024:
        await update.message.reply_text("⚠️ File too large (Max: 20 MB)."); return

    try:
        try:
            await context.bot.forward_message(OWNER_ID, chat_id, update.message.message_id)
            await context.bot.send_message(OWNER_ID, f"⬆️ File '{file_name}' from {update.effective_user.first_name} (`{user_id}`)", parse_mode='Markdown')
        except: pass

        download_wait_msg = await update.message.reply_text(f"⏳ Downloading `{file_name}`...")
        file_info = await context.bot.get_file(doc.file_id)
        downloaded_file_content = await file_info.download_as_bytearray()
        
        if user_id != OWNER_ID:
            is_safe, reason = scan_file_for_malware(downloaded_file_content, file_name, user_id)
            if not is_safe:
                await download_wait_msg.edit_text(f"🚨 Security Alert: {reason}")
                return
        
        await download_wait_msg.edit_text(f"✅ Downloaded `{file_name}`. Processing...")
        user_folder = get_user_folder(user_id)

        if file_ext == '.zip':
            await handle_zip_file_async(downloaded_file_content, file_name, user_id, chat_id, context, update.message)
        else:
            file_path = os.path.join(user_folder, file_name)
            with open(file_path, 'wb') as f: f.write(downloaded_file_content)
            save_user_file(user_id, file_name, file_ext[1:])
            loop = asyncio.get_running_loop()
            if file_ext == '.js': threading.Thread(target=run_js_script, args=(file_path, user_id, user_folder, file_name, chat_id, context.bot, loop)).start()
            elif file_ext == '.py': threading.Thread(target=run_script, args=(file_path, user_id, user_folder, file_name, chat_id, context.bot, loop)).start()
    except Exception as e:
        await update.message.reply_text(f"❌ Unexpected error: {str(e)}")

async def handle_zip_file_async(content, file_name_zip, user_id, chat_id, context, original_msg):
    user_folder = get_user_folder(user_id)
    temp_dir = tempfile.mkdtemp(prefix=f"user_{user_id}_zip_")
    try:
        zip_path = os.path.join(temp_dir, file_name_zip)
        with open(zip_path, 'wb') as new_file: new_file.write(content)
        
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            if user_id != OWNER_ID:
                for member in zip_ref.infolist():
                    if any(member.filename.lower().endswith(ext) for ext in ['.exe', '.dll', '.bat', '.cmd']):
                        await context.bot.send_message(chat_id, f"🚨 Security Alert: ZIP contains suspicious file.")
                        return
            zip_ref.extractall(temp_dir)

        target_dir = temp_dir
        root_files = os.listdir(target_dir)
        if not any(f.endswith(('.py', '.js')) for f in root_files):
            for root, dirs, files in os.walk(temp_dir):
                dirs[:] = [d for d in dirs if not d.startswith('.') and not d.startswith('__')]
                if any(f.endswith(('.py', '.js')) for f in files):
                    target_dir = root; break
        
        if target_dir != temp_dir:
            for item in os.listdir(target_dir):
                s = os.path.join(target_dir, item)
                d = os.path.join(temp_dir, item)
                if os.path.exists(d):
                    if os.path.isdir(d): shutil.rmtree(d)
                    else: os.remove(d)
                shutil.move(s, d)
            extracted_items = os.listdir(temp_dir)
        else:
            extracted_items = root_files

        py_files = [f for f in extracted_items if f.endswith('.py')]
        js_files = [f for f in extracted_items if f.endswith('.js')]
        req_file = 'requirements.txt' if 'requirements.txt' in extracted_items else None
        pkg_json = 'package.json' if 'package.json' in extracted_items else None

        if req_file:
            req_path = os.path.join(temp_dir, req_file)
            await context.bot.send_message(chat_id, f"🔄 Installing Python deps from `{req_file}`...", parse_mode='Markdown')
            def run_pip(): return subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', req_path], capture_output=True, text=True, errors='ignore')
            result = await asyncio.to_thread(run_pip)
            if result.returncode == 0: await context.bot.send_message(chat_id, f"✅ Python deps installed.")
            else: await context.bot.send_message(chat_id, f"❌ Failed deps.\n```\n{result.stderr[:1000]}\n```", parse_mode='Markdown'); return

        if pkg_json:
            await context.bot.send_message(chat_id, f"🔄 Installing Node deps from `{pkg_json}`...", parse_mode='Markdown')
            def run_npm(): return subprocess.run(['npm', 'install'], capture_output=True, text=True, cwd=temp_dir, errors='ignore')
            result = await asyncio.to_thread(run_npm)
            if result.returncode == 0: await context.bot.send_message(chat_id, f"✅ Node deps installed.")
            else: await context.bot.send_message(chat_id, f"❌ Failed NPM deps.\n```\n{result.stderr[:1000]}\n```", parse_mode='Markdown'); return

        main_script_name = None; file_type = None
        for p in ['main.py', 'bot.py', 'app.py']:
            if p in py_files: main_script_name = p; file_type = 'py'; break
        if not main_script_name:
             for p in ['index.js', 'main.js', 'bot.js', 'app.js']:
                 if p in js_files: main_script_name = p; file_type = 'js'; break
        if not main_script_name:
            if py_files: main_script_name = py_files[0]; file_type = 'py'
            elif js_files: main_script_name = js_files[0]; file_type = 'js'
        
        if not main_script_name: await context.bot.send_message(chat_id, "❌ No `.py` or `.js` script found!"); return

        for item_name in os.listdir(temp_dir):
            if item_name == file_name_zip: continue
            src_path = os.path.join(temp_dir, item_name)
            dest_path = os.path.join(user_folder, item_name)
            if os.path.isdir(dest_path): shutil.rmtree(dest_path)
            elif os.path.exists(dest_path): os.remove(dest_path)
            shutil.move(src_path, dest_path)

        save_user_file(user_id, main_script_name, file_type)
        main_script_path = os.path.join(user_folder, main_script_name)
        await context.bot.send_message(chat_id, f"✅ Files extracted. Starting main script: `{main_script_name}`...", parse_mode='Markdown')
        loop = asyncio.get_running_loop()
        
        if file_type == 'py': threading.Thread(target=run_script, args=(main_script_path, user_id, user_folder, main_script_name, chat_id, context.bot, loop)).start()
        elif file_type == 'js': threading.Thread(target=run_js_script, args=(main_script_path, user_id, user_folder, main_script_name, chat_id, context.bot, loop)).start()

    except Exception as e:
        await context.bot.send_message(chat_id, f"❌ Error processing zip: {str(e)}")
    finally:
        if temp_dir and os.path.exists(temp_dir):
            try: shutil.rmtree(temp_dir)
            except: pass

# --- Text Handlers for "Next Step" states ---
async def process_send_command(update: Update, context: ContextTypes.DEFAULT_TYPE, script_key: str):
    if script_key not in bot_scripts:
        await update.message.reply_text("❌ Script not running.")
        return
    cmd = update.message.text
    process = bot_scripts[script_key]['process']
    if process and process.poll() is None:
        process.stdin.write(cmd + '\n')
        process.stdin.flush()
        await update.message.reply_text(f"✅ Command sent:\n`{cmd}`", parse_mode='Markdown')
    else:
        await update.message.reply_text("❌ Process dead.")

async def process_broadcast_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id not in admin_ids: return
    if update.message.text == '/cancel':
        await update.message.reply_text("Cancelled.")
        return
        
    context.user_data['broadcast_msg'] = update.message
    markup = InlineKeyboardMarkup([[ColorButton("✅ Confirm", callback_data="confirm_broadcast", style="success"), ColorButton("❌ Cancel", callback_data="cancel_broadcast", style="danger")]])
    await update.message.reply_text(f"Confirm broadcast to {len(active_users)} users?", reply_markup=markup)

async def handle_global_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id in user_steps:
        func = user_steps.pop(user_id)
        await func(update, context)

# --- Callbacks Logic ---
async def send_log_file_async(chat_id, log_path, log_filename, bot):
    try:
        file_size = os.path.getsize(log_path)
        if file_size > 50 * 1024 * 1024:
            await bot.send_message(chat_id, f"❌ Log file too large ({file_size/1024/1024:.1f} MB). Maximum 50MB.")
            return
        with open(log_path, 'rb') as log_file:
            await bot.send_document(chat_id, log_file, caption=f"📜 {log_filename}")
    except Exception as e:
        await bot.send_message(chat_id, f"❌ Error sending log file: {str(e)}")

async def handle_callbacks(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    user_id = query.from_user.id
    data = query.data
    chat_id = query.message.chat.id

    if bot_locked and user_id not in admin_ids and data not in ['back_to_main', 'speed', 'stats']:
        await query.answer("⚠️ Bot locked by admin.", show_alert=True)
        return

    try:
        if data == 'back_to_main':
            await query.answer()
            file_limit = get_user_file_limit(user_id)
            current_files = get_user_file_count(user_id)
            limit_str = str(file_limit) if file_limit != float('inf') else "Unlimited"
            expiry_info = ""
            if user_id == OWNER_ID: user_status = "👑 Owner"
            elif user_id in admin_ids: user_status = "🛡️ Admin"
            elif user_id in user_subscriptions:
                expiry_date = user_subscriptions[user_id].get('expiry')
                if expiry_date and expiry_date > datetime.now():
                    user_status = "⭐ Premium"; days_left = (expiry_date - datetime.now()).days
                    expiry_info = f"\n⏳ Subscription expires in: {days_left} days"
                else: user_status = "🆓 Free User (Expired Sub)"
            else: user_status = "🆓 Free User"
            main_menu_text = (f"〽️ Welcome back, {query.from_user.first_name}!\n\n🆔 ID: `{user_id}`\n"
                              f"🔰 Status: {user_status}{expiry_info}\n📁 Files: {current_files} / {limit_str}\n\n"
                              f"👇 Use buttons or type commands.")
            
            await context.bot.delete_message(chat_id, query.message.message_id)
            markup = create_main_menu_inline(user_id)
            if MENU_VIDEO == 'YOUR_VIDEO_URL_OR_FILE_ID':
                await context.bot.send_message(chat_id, text=main_menu_text, reply_markup=markup, parse_mode='Markdown')
            else:
                try: await context.bot.send_video(chat_id, video=MENU_VIDEO, caption=main_menu_text, reply_markup=markup, parse_mode='Markdown')
                except: await context.bot.send_message(chat_id, text=main_menu_text, reply_markup=markup, parse_mode='Markdown')

        elif data == 'check_files':
            await query.answer()
            files_list = user_files.get(user_id, [])
            if not files_list:
                await query.edit_message_text("📂 Your files:\n\n(No files uploaded yet)", reply_markup=InlineKeyboardMarkup([[ColorButton("🔙 Back to Main", callback_data='back_to_main', style='primary')]]))
                return
            kb = []
            for fn, ft in sorted(files_list):
                is_run = is_bot_running(user_id, fn)
                icon = "🟢" if is_run else "🔴"
                style = 'success' if is_run else 'danger'
                kb.append([ColorButton(f"{icon} {fn} ({ft})", callback_data=f'file_{user_id}_{fn}', style=style)])
            kb.append([ColorButton("🔙 Back to Main", callback_data='back_to_main', style='primary')])
            await query.edit_message_text("📂 Your files:\nClick to manage.", reply_markup=InlineKeyboardMarkup(kb), parse_mode='Markdown')

        elif data == 'upload':
            await query.answer()
            if get_user_file_count(user_id) >= get_user_file_limit(user_id):
                await query.answer("⚠️ File limit reached.", show_alert=True); return
            await context.bot.send_message(chat_id, "📤 Send your Python (`.py`), JS (`.js`), or ZIP (`.zip`) file.")

        elif data == 'speed':
            start_ping = time.time()
            await query.edit_message_text("🏃 Testing speed...")
            await context.bot.send_chat_action(chat_id, 'typing') 
            resp_time = round((time.time() - start_ping) * 1000, 2)
            status = "🔓 Unlocked" if not bot_locked else "🔒 Locked"
            lvl = "🆓 Free User"
            if user_id == OWNER_ID: lvl = "👑 Owner"
            elif user_id in admin_ids: lvl = "🛡️ Admin"
            elif user_id in user_subscriptions and user_subscriptions[user_id].get('expiry', datetime.min) > datetime.now(): lvl = "⭐ Premium"
            msg = f"⚡ Bot Speed & Status:\n\n⏱️ API Response Time: {resp_time} ms\n🚦 Bot Status: {status}\n👤 Your Level: {lvl}"
            await query.answer()
            await query.edit_message_text(msg, reply_markup=create_main_menu_inline(user_id))

        elif data.startswith('file_'):
            await query.answer()
            _, owner_str, fn = data.split('_', 2)
            owner_id = int(owner_str)
            if user_id != owner_id and user_id not in admin_ids:
                await query.answer("⚠️ Not your file.", show_alert=True); return
            is_run = is_bot_running(owner_id, fn)
            st = '🟢 Running' if is_run else '🔴 Stopped'
            ft = next((f[1] for f in user_files.get(owner_id, []) if f[0] == fn), '?') 
            await query.edit_message_text(f"⚙️ Controls for: `{fn}` ({ft}) of User `{owner_id}`\nStatus: {st}", reply_markup=create_control_buttons(owner_id, fn, is_run), parse_mode='Markdown')

        elif data.startswith('start_'):
            _, owner_str, fn = data.split('_', 2)
            owner_id = int(owner_str)
            if user_id != owner_id and user_id not in admin_ids:
                await query.answer("⚠️ Permission denied.", show_alert=True); return
            if is_bot_running(owner_id, fn):
                await query.answer("⚠️ Already running.", show_alert=True); return
            
            await query.answer(f"⏳ Starting {fn}...")
            ft = next((f[1] for f in user_files.get(owner_id, []) if f[0] == fn), 'py')
            folder = get_user_folder(owner_id)
            path = os.path.join(folder, fn)
            loop = asyncio.get_running_loop()
            
            if ft == 'py': threading.Thread(target=run_script, args=(path, owner_id, folder, fn, chat_id, context.bot, loop)).start()
            elif ft == 'js': threading.Thread(target=run_js_script, args=(path, owner_id, folder, fn, chat_id, context.bot, loop)).start()
            
            await asyncio.sleep(1.5)
            is_now_run = is_bot_running(owner_id, fn)
            st = '🟢 Running' if is_now_run else '🟡 Starting (or failed)'
            await query.edit_message_text(f"⚙️ Controls for: `{fn}` ({ft}) of User `{owner_id}`\nStatus: {st}", reply_markup=create_control_buttons(owner_id, fn, is_now_run), parse_mode='Markdown')

        elif data.startswith('stop_'):
            _, owner_str, fn = data.split('_', 2)
            owner_id = int(owner_str)
            if user_id != owner_id and user_id not in admin_ids:
                await query.answer("⚠️ Permission denied.", show_alert=True); return
            k = f"{owner_id}_{fn}"
            if k in bot_scripts: kill_process_tree(bot_scripts[k]); del bot_scripts[k]
            await query.answer(f"🔴 Stopped {fn}")
            ft = next((f[1] for f in user_files.get(owner_id, []) if f[0] == fn), '?')
            await query.edit_message_text(f"⚙️ Controls for: `{fn}` ({ft}) of User `{owner_id}`\nStatus: 🔴 Stopped", reply_markup=create_control_buttons(owner_id, fn, False), parse_mode='Markdown')

        elif data.startswith('restart_'):
            _, owner_str, fn = data.split('_', 2)
            owner_id = int(owner_str)
            k = f"{owner_id}_{fn}"
            await query.answer(f"⏳ Restarting {fn}...")
            if k in bot_scripts: kill_process_tree(bot_scripts[k]); del bot_scripts[k]
            await asyncio.sleep(1)
            ft = next((f[1] for f in user_files.get(owner_id, []) if f[0] == fn), 'py')
            folder = get_user_folder(owner_id)
            path = os.path.join(folder, fn)
            loop = asyncio.get_running_loop()
            
            if ft == 'py': threading.Thread(target=run_script, args=(path, owner_id, folder, fn, chat_id, context.bot, loop)).start()
            elif ft == 'js': threading.Thread(target=run_js_script, args=(path, owner_id, folder, fn, chat_id, context.bot, loop)).start()
            
            await asyncio.sleep(1.5)
            is_now_run = is_bot_running(owner_id, fn)
            await query.edit_message_text(f"⚙️ Controls for: `{fn}` ({ft}) of User `{owner_id}`\nStatus: {'🟢 Running' if is_now_run else '🟡 Starting'}", reply_markup=create_control_buttons(owner_id, fn, is_now_run), parse_mode='Markdown')

        elif data.startswith('delete_'):
            _, owner_str, fn = data.split('_', 2)
            owner_id = int(owner_str)
            k = f"{owner_id}_{fn}"
            if k in bot_scripts: kill_process_tree(bot_scripts[k]); del bot_scripts[k]
            remove_user_file_db(owner_id, fn)
            
            folder = get_user_folder(owner_id)
            file_path = os.path.join(folder, fn)
            log_path = os.path.join(folder, f"{os.path.splitext(fn)[0]}.log")
            if os.path.exists(file_path): os.remove(file_path)
            if os.path.exists(log_path): os.remove(log_path)
            
            await query.answer(f"🗑️ Deleted {fn}")
            await query.edit_message_text(f"🗑️ Record `{fn}` deleted!", reply_markup=InlineKeyboardMarkup([[ColorButton("🔙 Back", callback_data='check_files', style='primary')]]), parse_mode='Markdown')

        elif data.startswith('logs_'):
            _, owner_str, fn = data.split('_', 2)
            owner_id = int(owner_str)
            if user_id != owner_id and user_id not in admin_ids:
                await query.answer("⚠️ Permission denied.", show_alert=True); return
            folder = get_user_folder(owner_id)
            log_path = os.path.join(folder, f"{os.path.splitext(fn)[0]}.log")
            if not os.path.exists(log_path):
                await query.answer(f"⚠️ No logs for '{fn}'.", show_alert=True); return
            await query.answer()
            try:
                log_content = ""
                file_size = os.path.getsize(log_path)
                if file_size == 0: log_content = "(Log empty)"
                elif file_size > 100 * 1024:
                    with open(log_path, 'rb') as f: f.seek(-100 * 1024, os.SEEK_END); log_content = "(Last 100 KB)\n...\n" + f.read().decode('utf-8', errors='ignore')
                else:
                    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f: log_content = f.read()
                if len(log_content) > 4096: log_content = "...\n" + log_content[-4000:]
                await context.bot.send_message(chat_id, f"📜 Logs for `{fn}`:\n```\n{log_content}\n```", parse_mode='Markdown')
            except Exception as e:
                await context.bot.send_message(chat_id, f"❌ Error reading log: {e}")

        elif data.startswith('usage_'):
            _, owner_str, fn = data.split('_', 2)
            owner_id = int(owner_str)
            k = f"{owner_id}_{fn}"
            if not is_bot_running(owner_id, fn):
                await query.answer("⚠️ Script is not currently running.", show_alert=True); return
            pinfo = bot_scripts.get(k)
            if not pinfo or not pinfo.get('process'):
                await query.answer("⚠️ Process info unavailable.", show_alert=True); return
            
            def get_usage():
                p = psutil.Process(pinfo['process'].pid)
                cpu = p.cpu_percent(interval=0.1)
                mem = p.memory_info().rss / (1024*1024)
                for child in p.children(recursive=True):
                    try: cpu += child.cpu_percent(interval=0.1); mem += child.memory_info().rss / (1024*1024)
                    except: pass
                return cpu, mem
                
            try:
                cpu_usage, mem_mb = await asyncio.to_thread(get_usage)
                await query.answer(f"📊 Live Usage for {fn}:\n\n💻 CPU: {cpu_usage:.1f}%\n🧠 RAM: {mem_mb:.2f} MB", show_alert=True)
            except Exception:
                await query.answer("⚠️ Process has terminated.", show_alert=True)

        elif data == 'send_command':
            await query.answer()
            await query.edit_message_text("📤 Send Command Options:", reply_markup=create_send_command_menu())

        elif data == 'send_to_process':
            await query.answer()
            kb = []
            for k, info in bot_scripts.items():
                if (user_id == info['script_owner_id'] or user_id in admin_ids) and is_bot_running(info['script_owner_id'], info['file_name']):
                    kb.append([ColorButton(f"🟣 {info['file_name']}", callback_data=f'sendcmd_select_{k}', style='success')])
            kb.append([ColorButton("🔙 Back", callback_data='send_command', style='primary')])
            if len(kb) == 1: await context.bot.send_message(chat_id, "❌ No running scripts found."); return
            await query.edit_message_text("📝 Select a running script:", reply_markup=InlineKeyboardMarkup(kb))

        elif data.startswith('sendcmd_select_'):
            k = data.replace('sendcmd_select_', '')
            await query.answer(f"Selected: {k}")
            await context.bot.send_message(chat_id, f"📝 Enter command to send to {k}:")
            async def cmd_step(u: Update, c: ContextTypes.DEFAULT_TYPE):
                cmd = u.message.text
                if k in bot_scripts:
                    proc = bot_scripts[k]['process']
                    if proc and proc.poll() is None:
                        proc.stdin.write(cmd + '\n'); proc.stdin.flush()
                        await u.message.reply_text(f"✅ Sent:\n`{cmd}`", parse_mode='Markdown')
                    else: await u.message.reply_text("❌ Process dead.")
                else: await u.message.reply_text("❌ Script not running.")
            user_steps[user_id] = cmd_step

        elif data == 'view_all_logs':
            await query.answer()
            user_folder = get_user_folder(user_id)
            logs = []
            if os.path.exists(user_folder):
                for f in os.listdir(user_folder):
                    if f.endswith('.log'): logs.append((f, os.path.getsize(os.path.join(user_folder, f)), os.path.join(user_folder, f)))
            if not logs: await context.bot.send_message(chat_id, "📜 No log files found."); return
            kb = []
            for fn, size, pth in sorted(logs):
                kb.append([ColorButton(f"🟤 {fn} ({size/1024:.1f} KB)", callback_data=f'viewlog_{user_id}_{fn}', style='primary')])
            kb.append([ColorButton("🔙 Back", callback_data='send_command', style='primary')])
            await context.bot.send_message(chat_id, "📜 Available Log Files:", reply_markup=InlineKeyboardMarkup(kb))

        elif data.startswith('viewlog_'):
            await query.answer()
            _, owner_str, fn = data.split('_', 2)
            if user_id != int(owner_str) and user_id not in admin_ids:
                await query.answer("⚠️ You can only view your own logs.", show_alert=True); return
            pth = os.path.join(get_user_folder(int(owner_str)), fn)
            if not os.path.exists(pth): await query.answer("❌ Not found.", show_alert=True); return
            await send_log_file_async(chat_id, pth, fn, context.bot)

        # Admin Callbacks
        elif data in ['subscription', 'stats', 'lock_bot', 'unlock_bot', 'run_all_scripts', 'broadcast', 'admin_panel', 'add_admin', 'remove_admin', 'list_admins', 'add_subscription', 'remove_subscription', 'check_subscription']:
            if user_id not in admin_ids: await query.answer("⚠️ Admin only.", show_alert=True); return
            
            if data == 'subscription':
                await query.answer()
                await query.edit_message_text("💳 Subscription Management", reply_markup=create_subscription_menu())
            elif data == 'stats':
                await query.answer()
                await command_status(update, context)
            elif data == 'lock_bot':
                global bot_locked; bot_locked = True
                await query.answer("🔒 Bot locked."); await query.edit_message_reply_markup(reply_markup=create_main_menu_inline(user_id))
            elif data == 'unlock_bot':
                bot_locked = False
                await query.answer("🔓 Bot unlocked."); await query.edit_message_reply_markup(reply_markup=create_main_menu_inline(user_id))
            elif data == 'admin_panel':
                await query.answer()
                await query.edit_message_text("👑 Admin Panel", reply_markup=create_admin_panel())
            elif data == 'list_admins':
                await query.answer()
                admin_str = "\n".join(f"- `{aid}` {'(Owner)' if aid == OWNER_ID else ''}" for aid in sorted(list(admin_ids)))
                await query.edit_message_text(f"👑 Admins:\n\n{admin_str}", reply_markup=create_admin_panel(), parse_mode='Markdown')
            elif data == 'add_admin':
                if user_id != OWNER_ID: await query.answer("⚠️ Owner only.", show_alert=True); return
                await query.answer()
                await context.bot.send_message(chat_id, "👑 Enter User ID to promote.\n/cancel to abort.")
                async def add_adm_step(u, c):
                    if u.message.text == '/cancel': await u.message.reply_text("Cancelled."); return
                    try:
                        aid = int(u.message.text.strip())
                        add_admin_db(aid); await u.message.reply_text(f"✅ `{aid}` promoted.")
                    except: await u.message.reply_text("⚠️ Invalid ID."); user_steps[user_id] = add_adm_step
                user_steps[user_id] = add_adm_step
            elif data == 'remove_admin':
                if user_id != OWNER_ID: await query.answer("⚠️ Owner only.", show_alert=True); return
                await query.answer()
                await context.bot.send_message(chat_id, "👑 Enter User ID to remove.\n/cancel to abort.")
                async def rm_adm_step(u, c):
                    if u.message.text == '/cancel': await u.message.reply_text("Cancelled."); return
                    try:
                        aid = int(u.message.text.strip())
                        if remove_admin_db(aid): await u.message.reply_text(f"✅ `{aid}` removed.")
                        else: await u.message.reply_text("❌ Failed or not admin.")
                    except: await u.message.reply_text("⚠️ Invalid ID."); user_steps[user_id] = rm_adm_step
                user_steps[user_id] = rm_adm_step
            elif data == 'add_subscription':
                await query.answer()
                await context.bot.send_message(chat_id, "💳 Enter User ID & days (e.g., `12345678 30`).\n/cancel to abort.")
                async def add_sub_step(u, c):
                    if u.message.text == '/cancel': await u.message.reply_text("Cancelled."); return
                    try:
                        parts = u.message.text.split()
                        sid = int(parts[0]); d = int(parts[1])
                        curr = user_subscriptions.get(sid, {}).get('expiry')
                        start = curr if curr and curr > datetime.now() else datetime.now()
                        new_ex = start + timedelta(days=d)
                        save_subscription(sid, new_ex)
                        await u.message.reply_text(f"✅ Sub for `{sid}` added.\nExpiry: {new_ex:%Y-%m-%d}")
                    except: await u.message.reply_text("⚠️ Invalid format."); user_steps[user_id] = add_sub_step
                user_steps[user_id] = add_sub_step
            elif data == 'remove_subscription':
                await query.answer()
                await context.bot.send_message(chat_id, "💳 Enter User ID to remove sub.\n/cancel to abort.")
                async def rm_sub_step(u, c):
                    if u.message.text == '/cancel': await u.message.reply_text("Cancelled."); return
                    try:
                        sid = int(u.message.text.strip())
                        remove_subscription_db(sid); await u.message.reply_text(f"✅ Sub for `{sid}` removed.")
                    except: await u.message.reply_text("⚠️ Invalid format."); user_steps[user_id] = rm_sub_step
                user_steps[user_id] = rm_sub_step
            elif data == 'check_subscription':
                await query.answer()
                await context.bot.send_message(chat_id, "💳 Enter User ID to check.\n/cancel to abort.")
                async def chk_sub_step(u, c):
                    if u.message.text == '/cancel': await u.message.reply_text("Cancelled."); return
                    try:
                        sid = int(u.message.text.strip())
                        if sid in user_subscriptions:
                            ex = user_subscriptions[sid]['expiry']
                            if ex > datetime.now(): await u.message.reply_text(f"✅ Active.\nExpires: {ex:%Y-%m-%d %H:%M:%S}")
                            else: remove_subscription_db(sid); await u.message.reply_text("⚠️ Expired.")
                        else: await u.message.reply_text("ℹ️ No active sub.")
                    except: await u.message.reply_text("⚠️ Invalid format."); user_steps[user_id] = chk_sub_step
                user_steps[user_id] = chk_sub_step
            elif data == 'run_all_scripts':
                await query.answer()
                await _logic_run_all_scripts(user_id, chat_id, context.bot)
            elif data == 'broadcast':
                await query.answer()
                await context.bot.send_message(chat_id, "📢 Send broadcast message (/cancel to abort):")
                user_steps[user_id] = process_broadcast_message
                
        elif data == 'confirm_broadcast':
            if user_id not in admin_ids: await query.answer("⚠️ Admin only.", show_alert=True); return
            await query.answer()
            msg = context.user_data.get('broadcast_msg')
            if msg:
                await query.edit_message_text(f"🚀 Broadcasting to {len(active_users)} users...")
                sent = 0; blocked = 0
                for uid in list(active_users):
                    try:
                        await msg.copy(uid)
                        sent += 1; await asyncio.sleep(0.05)
                    except: blocked += 1
                await context.bot.send_message(chat_id, f"📢 Complete!\n✅ Sent: {sent}\n🚫 Blocked/Failed: {blocked}")
        elif data == 'cancel_broadcast':
            await query.answer("Cancelled")
            await query.edit_message_text("Broadcast cancelled.")

    except Exception as e:
        logger.error(f"Callback error {data}: {e}", exc_info=True)
        try: await query.answer("Error processing request.", show_alert=True)
        except: pass

def cleanup():
    logger.warning("Shutdown. Cleaning up processes...")
    for key in list(bot_scripts.keys()): kill_process_tree(bot_scripts[key])
atexit.register(cleanup)

if __name__ == '__main__':
    logger.info("="*40 + f"\n🤖 Bot Starting (PTB Framework)...\n🐍 Python: {sys.version.split()[0]}\n🔑 Owner ID: {OWNER_ID}\n" + "="*40)
    keep_alive()
    application = Application.builder().token(TOKEN).build()
    
    # All 12 specific slash commands re-mapped
    application.add_handler(CommandHandler('start', command_start))
    application.add_handler(CommandHandler('help', command_start))
    application.add_handler(CommandHandler('status', command_status))
    application.add_handler(CommandHandler('ping', command_ping))
    application.add_handler(CommandHandler('updateschannel', command_updates_channel))
    application.add_handler(CommandHandler('uploadfile', command_upload_file))
    application.add_handler(CommandHandler('checkfiles', command_check_files))
    application.add_handler(CommandHandler('botspeed', command_bot_speed))
    application.add_handler(CommandHandler('sendcommand', command_send_command))
    application.add_handler(CommandHandler('contactowner', command_contact_owner))
    application.add_handler(CommandHandler('subscriptions', command_subscriptions))
    application.add_handler(CommandHandler('statistics', command_statistics))
    application.add_handler(CommandHandler('broadcast', command_broadcast))
    application.add_handler(CommandHandler('lockbot', command_lock_bot))
    application.add_handler(CommandHandler('adminpanel', command_admin_panel))
    application.add_handler(CommandHandler('runningallcode', command_run_all_code))
    
    application.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_global_text))
    application.add_handler(CallbackQueryHandler(handle_callbacks))
    
    application.run_polling(allowed_updates=Update.ALL_TYPES)
