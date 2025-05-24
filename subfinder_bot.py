import os
import re
import random
import time
import tempfile
import requests
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from abc import ABC, abstractmethod
from bs4 import BeautifulSoup
from rich.console import Console
from flask import Flask, request
from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    filters,
    ContextTypes,
)
import logging
import json

# Configure logging for detailed debugging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# HTTP headers and user agents for subdomain source requests
HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Connection": "keep-alive",
}
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36",
]

# Console class for formatted output
class SubFinderConsole(Console):
    def __init__(self):
        super().__init__()
        self.total_subdomains = 0
        self.domain_stats = {}

    def print_domain_start(self, domain):
        self.print(f"[cyan]Processing: {domain}[/cyan]")
    
    def update_domain_stats(self, domain, count):
        self.domain_stats[domain] = count
        self.total_subdomains += count
    
    def print_domain_complete(self, domain, count):
        self.print(f"[green]{domain}: {count} subdomains found[/green]")
    
    def print_final_summary(self, output_file):
        print("\r\033[K", end="")
        self.print(f"\n[green]Total: [bold]{self.total_subdomains}[/bold] subdomains found")
        self.print(f"[green]Results saved to {output_file}[/green]")

    def print_progress(self, current, total):
        self.print(f"Progress: {current} / {total}", end="\r")
    
    def print_error(self, message):
        self.print(f"[red]{message}[/red]")

# Request handler for HTTP requests to subdomain sources
class RequestHandler:
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

    def _get_headers(self):
        headers = HEADERS.copy()
        headers["user-agent"] = random.choice(USER_AGENTS)
        return headers

    def get(self, url, timeout=10):
        try:
            response = self.session.get(url, timeout=timeout, headers=self._get_headers())
            if response.status_code == 200:
                return response
        except requests.RequestException as e:
            logger.error(f"Request failed for {url}: {str(e)}")
        return None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session.close()

# Domain validation utility
class DomainValidator:
    DOMAIN_REGEX = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
        r'[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]$'
    )

    @classmethod
    def is_valid_domain(cls, domain):
        return bool(
            domain
            and isinstance(domain, str)
            and cls.DOMAIN_REGEX.match(domain)
        )

    @staticmethod
    def filter_valid_subdomains(subdomains, domain):
        if not domain or not isinstance(domain, str):
            return set()

        domain_suffix = f".{domain}"
        result = set()

        for sub in subdomains:
            if not isinstance(sub, str):
                continue
            if sub == domain or sub.endswith(domain_suffix):
                result.add(sub)
        return result

# Cursor manager for hiding/showing cursor in console
class CursorManager:
    def __enter__(self):
        print('\033[?25l', end='', flush=True)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        print('\033[?25h', end='', flush=True)

# Abstract base class for subdomain sources
class SubdomainSource(RequestHandler, ABC):
    def __init__(self, name):
        super().__init__()
        self.name = name

    @abstractmethod
    def fetch(self, domain):
        pass

# Subdomain source implementations
class CrtshSource(SubdomainSource):
    def __init__(self):
        super().__init__("Crt.sh")

    def fetch(self, domain):
        subdomains = set()
        response = self.get(f"https://crt.sh/?q=%25.{domain}&output=json")
        if response and response.headers.get('Content-Type') == 'application/json':
            for entry in response.json():
                subdomains.update(entry['name_value'].splitlines())
        return subdomains

class HackertargetSource(SubdomainSource):
    def __init__(self):
        super().__init__("Hackertarget")

    def fetch(self, domain):
        subdomains = set()
        response = self.get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
        if response and 'text' in response.headers.get('Content-Type', ''):
            subdomains.update(
                [line.split(",")[0] for line in response.text.splitlines()]
            )
        return subdomains

class RapidDnsSource(SubdomainSource):
    def __init__(self):
        super().__init__("RapidDNS")

    def fetch(self, domain):
        subdomains = set()
        response = self.get(f"https://rapiddns.io/subdomain/{domain}?full=1")
        if response:
            soup = BeautifulSoup(response.text, 'html.parser')
            for link in soup.find_all('td'):
                text = link.get_text(strip=True)
                if text.endswith(f".{domain}"):
                    subdomains.add(text)
        return subdomains

class AnubisDbSource(SubdomainSource):
    def __init__(self):
        super().__init__("AnubisDB")

    def fetch(self, domain):
        subdomains = set()
        response = self.get(f"https://jldc.me/anubis/subdomains/{domain}")
        if response:
            subdomains.update(response.json())
        return subdomains

class AlienVaultSource(SubdomainSource):
    def __init__(self):
        super().__init__("AlienVault")

    def fetch(self, domain):
        subdomains = set()
        response = self.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns")
        if response:
            for entry in response.json().get("passive_dns", []):
                hostname = entry.get("hostname")
                if hostname:
                    subdomains.add(hostname)
        return subdomains

class CertSpotterSource(SubdomainSource):
    def __init__(self):
        super().__init__("CertSpotter")

    def fetch(self, domain):
        subdomains = set()
        response = self.get(f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names")
        if response:
            for cert in response.json():
                subdomains.update(cert.get('dns_names', []))
        return subdomains

class C99Source(SubdomainSource):
    def __init__(self):
        super().__init__("C99")

    def fetch(self, domain):
        subdomains = set()
        dates = [(datetime.datetime.now() - datetime.timedelta(days=i)).strftime('%Y-%m-%d') 
                for i in range(7)]
        
        for date in dates:
            url = f"https://subdomainfinder.c99.nl/scans/{date}/{domain}"
            response = self.get(url)
            if response:
                soup = BeautifulSoup(response.text, 'html.parser')
                for link in soup.select('td a.link.sd'):
                    text = link.get_text(strip=True)
                    if text.endswith(f".{domain}"):
                        subdomains.add(text)
                if subdomains:
                    break
        return subdomains

def get_sources():
    return [
        CrtshSource(),
        HackertargetSource(),
        RapidDnsSource(),
        AnubisDbSource(),
        AlienVaultSource(),
        CertSpotterSource(),
        C99Source()
    ]

# Main SubFinder class
class SubFinder:
    def __init__(self):
        self.console = SubFinderConsole()
        self.completed = 0
        self.cursor_manager = CursorManager()

    def _fetch_from_source(self, source, domain):
        try:
            found = source.fetch(domain)
            return DomainValidator.filter_valid_subdomains(found, domain)
        except Exception as e:
            logger.error(f"Error fetching from {source.name} for {domain}: {str(e)}")
            return set()

    @staticmethod
    def save_subdomains(subdomains, output_file, max_file_size=50*1024*1024):  # 50MB
        if not subdomains:
            return []

        output_files = []
        current_file = output_file
        part_number = 1
        current_size = 0
        current_subdomains = []

        # Check if base file already exists and determine next part number
        if os.path.exists(output_file):
            base, ext = os.path.splitext(output_file)
            while os.path.exists(current_file):
                part_number += 1
                current_file = f"{base}_part{part_number}{ext}"
        output_files.append(current_file)

        for sub in sorted(subdomains):
            line = sub + "\n"
            line_size = len(line.encode('utf-8'))
            if current_size + line_size > max_file_size:
                # Write current batch to file
                with open(current_file, "a", encoding="utf-8") as f:
                    f.write("".join(current_subdomains))
                current_subdomains = [line]
                current_size = line_size
                part_number += 1
                base, ext = os.path.splitext(output_file)
                current_file = f"{base}_part{part_number}{ext}"
                output_files.append(current_file)
            else:
                current_subdomains.append(line)
                current_size += line_size

        # Write remaining subdomains
        if current_subdomains:
            with open(current_file, "a", encoding="utf-8") as f:
                f.write("".join(current_subdomains))

        return output_files

    def process_domain(self, domain, output_file, sources, total):
        if not DomainValidator.is_valid_domain(domain):
            self.completed += 1
            return set()

        self.console.print_domain_start(domain)
        self.console.print_progress(self.completed, total)
        
        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = [
                executor.submit(self._fetch_from_source, source, domain)
                for source in sources
            ]
            results = [f.result() for f in as_completed(futures)]

        subdomains = set().union(*results) if results else set()

        self.console.update_domain_stats(domain, len(subdomains))
        self.console.print_domain_complete(domain, len(subdomains))
        self.save_subdomains(subdomains, output_file)

        self.completed += 1
        self.console.print_progress(self.completed, total)
        return subdomains

    async def run(self, domains, output_file, sources, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not domains:
            await update.message.reply_text("No valid domains provided")
            return

        os.makedirs(os.path.dirname(output_file) or '.', exist_ok=True)
        self.completed = 0
        all_subdomains = set()
        total = len(domains)
        batch_size = 100  # Process domains in batches to manage memory

        with self.cursor_manager:
            for i in range(0, total, batch_size):
                batch = domains[i:i + batch_size]
                with ThreadPoolExecutor(max_workers=3) as executor:
                    futures = [
                        executor.submit(self.process_domain, domain, output_file, sources, total)
                        for domain in batch
                    ]
                    for future in as_completed(futures):
                        try:
                            result = future.result()
                            all_subdomains.update(result)
                            # Send progress update to Telegram
                            progress_message = f"Progress: {self.completed}/{total}"
                            await update.message.reply_text(progress_message)
                        except Exception as e:
                            logger.error(f"Error processing domain: {str(e)}")
                            await update.message.reply_text(f"Error processing domain: {str(e)}")

            self.console.print_final_summary(output_file)
            try:
                await update.message.reply_text(
                    f"Total: {self.console.total_subdomains} subdomains found\nResults saved to {output_file}"
                )
            except Exception as e:
                logger.error(f"Failed to send final message: {str(e)}")
                return

            # Send output files to the user
            output_files = self.save_subdomains(all_subdomains, output_file)
            for file in output_files:
                if os.path.exists(file):
                    file_size = os.path.getsize(file)
                    if file_size > 50 * 1024 * 1024:  # 50MB
                        await update.message.reply_text(f"File {file} exceeds 50MB and cannot be sent via Telegram.")
                        continue
                    with open(file, 'rb') as f:
                        try:
                            await update.message.reply_document(document=f, filename=os.path.basename(file))
                        except Exception as e:
                            logger.error(f"Failed to send file {file}: {str(e)}")
                            await update.message.reply_text(f"Failed to send file {file}: {str(e)}")
            return all_subdomains

# Flask app for webhook
app = Flask(__name__)

# Telegram bot handlers
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        await update.message.reply_text(
            "Welcome to SubFinder Bot! Send a .txt file with one domain per line or a text message with domains (one per line)."
        )
    except Exception as e:
        logger.error(f"Failed to send start message: {str(e)}")

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # Check if user is authorized (optional, configurable via environment variable)
    allowed_users = os.getenv("ALLOWED_USERS", "").split(",")
    chat_id = str(update.effective_chat.id)
    if allowed_users and allowed_users != [''] and chat_id not in allowed_users:
        try:
            await update.message.reply_text(
                "❌ Restricted to specific users.", 
                reply_to_message_id=update.message.message_id
            )
        except Exception as e:
            logger.error(f"Failed to send restricted message: {str(e)}")
        return

    subfinder = SubFinder()
    sources = get_sources()
    domains = []

    try:
        if update.message.document:
            # Handle file input
            file = await update.message.document.get_file()
            file_path = os.path.join(tempfile.gettempdir(), update.message.document.file_name)
            await file.download_to_drive(file_path)
            
            if not file_path.endswith('.txt'):
                await update.message.reply_text("Please upload a .txt file with one domain per line.")
                os.remove(file_path)
                return

            file_size = os.path.getsize(file_path)
            if file_size > 100 * 1024 * 1024:  # 100MB limit
                await update.message.reply_text("Input file exceeds 100MB. Please use a smaller file.")
                os.remove(file_path)
                return

            with open(file_path, 'r') as f:
                domains = [d.strip() for d in f if DomainValidator.is_valid_domain(d.strip())]
            output_file = f"{file_path.rsplit('.', 1)[0]}_subdomains.txt"
            os.remove(file_path)  # Clean up temporary file
        else:
            # Handle text message input
            text = update.message.text
            domains = [d.strip() for d in text.splitlines() if DomainValidator.is_valid_domain(d.strip())]
            output_file = "subdomains.txt" if domains else "subdomains.txt"

        if not domains:
            await update.message.reply_text("No valid domains provided.")
            return

        if len(domains) > 1000:
            await update.message.reply_text("Too many domains (max 1000). Please reduce the number of domains.")
            return

        await update.message.reply_text(f"Processing {len(domains)} domain(s)...")
        await subfinder.run(domains, output_file, sources, update, context)
    except Exception as e:
        logger.error(f"Error in handle_message: {str(e)}")
        try:
            await update.message.reply_text(f"An error occurred: {str(e)}")
        except Exception as e:
            logger.error(f"Failed to send error message: {str(e)}")

# Flask route for webhook
@app.route('/telegram', methods=['POST'])
async def webhook():
    try:
        data = request.get_json(force=True)
        if not data:
            logger.error("No JSON data received in webhook")
            return {"error": "No JSON data"}, 400
        update = Update.de_json(data, application.bot)
        if update:
            await application.process_update(update)
        return {"ok": True}
    except Exception as e:
        logger.error(f"Webhook error: {str(e)}")
        return {"error": str(e)}, 500

@app.route('/health', methods=['GET'])
def health():
    return {"status": "healthy"}, 200

def set_webhook():
    bot_token = os.getenv("TELEGRAM_BOT_TOKEN")
    webhook_url = os.getenv("WEBHOOK_URL")
    if not bot_token or not webhook_url:
        logger.error("TELEGRAM_BOT_TOKEN or WEBHOOK_URL not set")
        return
    try:
        response = requests.get(
            f"https://api.telegram.org/bot{bot_token}/setWebhook?url={webhook_url}",
            timeout=10
        )
        if response.status_code == 200:
            logger.info(f"Webhook set to: {webhook_url}")
        else:
            logger.error(f"Failed to set webhook: {response.text}")
    except Exception as e:
        logger.error(f"Error setting webhook: {str(e)}")

def main():
    global application
    bot_token = os.getenv("TELEGRAM_BOT_TOKEN")
    if not bot_token:
        logger.error("TELEGRAM_BOT_TOKEN environment variable not set")
        return

    # Initialize the bot
    application = Application.builder().token(bot_token).build()

    # Add handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    application.add_handler(MessageHandler(filters.Document.TEXT, handle_message))

    # Set webhook
    set_webhook()

    # Start Flask server
    port = int(os.getenv("PORT", 8080))
    logger.info("Bot is running...")
    app.run(host="0.0.0.0", port=port)

if __name__ == '__main__':
    main()