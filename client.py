import os
import asyncio
import aiohttp
import aiofiles
import platform
import json
import time
from datetime import datetime, timedelta
from random import randint
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import colorama
from colorama import Fore, Style, Back
from typing import Dict, Optional, Any
from dataclasses import dataclass, asdict
from pathlib import Path
import logging
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.logging import RichHandler
from rich.table import Table
from rich.panel import Panel

# Initialize colorama and rich console
colorama.init()
console = Console()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[RichHandler(rich_tracebacks=True)]
)
logger = logging.getLogger("hwid_client")

@dataclass
class Settings:
    total_day: int = 36600
    commit_freq: int = 100
    variability: bool = False
    repo_link: str = "https://github.com/username/repo.git"
    commit_message_template: str = "commit #{}"
    author_name: str = "PG Mohd Azhan FIkri"
    author_email: str = "harrydotmyx@gmail.com"

class HWIDClient:
    def __init__(self):
        self.settings = Settings()
        self.SETTINGS_FILE = Path("settings.dll")
        self.ENCRYPTION_KEY_FILE = Path("key.key")
        self.API_URL = "https://hwid.akierry.io/api/verify-hwid/"
        self.MAX_RETRIES = 3
        self.RETRY_DELAY = 2
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Initialize encryption and settings
        try:
            self.cipher_suite = self.init_encryption()
            self.load_settings()
        except Exception as e:
            logger.error(f"Initialization Error: {e}")
            raise

    def init_encryption(self) -> Fernet:
        """Initialize encryption with PBKDF2 key derivation"""
        try:
            if not self.ENCRYPTION_KEY_FILE.exists():
                # Generate a strong key using PBKDF2
                salt = os.urandom(16)
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                )
                key = base64.urlsafe_b64encode(kdf.derive(os.urandom(32)))
                
                # Save the key
                self.ENCRYPTION_KEY_FILE.write_bytes(key)
            else:
                key = self.ENCRYPTION_KEY_FILE.read_bytes()
                
            return Fernet(key)
        except Exception as e:
            raise Exception(f"Failed to initialize encryption: {e}")

    def save_settings(self) -> None:
        """Save encrypted settings with backup"""
        backup_path = None
        try:
            # Create backup of existing settings
            if self.SETTINGS_FILE.exists():
                backup_path = self.SETTINGS_FILE.with_suffix('.bak')
                self.SETTINGS_FILE.rename(backup_path)

            # Save new settings
            settings_data = json.dumps(asdict(self.settings))
            encrypted_data = self.cipher_suite.encrypt(settings_data.encode())
            self.SETTINGS_FILE.write_bytes(encrypted_data)

            # Remove backup if save was successful
            if backup_path and backup_path.exists():
                backup_path.unlink()
                
        except Exception as e:
            logger.error(f"Failed to save settings: {e}")
            # Restore backup if it exists
            if backup_path and backup_path.exists():
                backup_path.rename(self.SETTINGS_FILE)
            raise

    def load_settings(self) -> None:
        """Load encrypted settings with validation"""
        if self.SETTINGS_FILE.exists():
            try:
                encrypted_data = self.SETTINGS_FILE.read_bytes()
                decrypted_data = self.cipher_suite.decrypt(encrypted_data).decode()
                settings_dict = json.loads(decrypted_data)
                
                # Validate settings
                for key, value in settings_dict.items():
                    if hasattr(self.settings, key):
                        setattr(self.settings, key, value)
                    else:
                        logger.warning(f"Unknown setting '{key}' found in settings file")
                        
            except Exception as e:
                logger.warning(f"Could not load settings: {e}")

    async def get_hwid(self) -> Optional[str]:
        """Get system HWID asynchronously"""
        try:
            # Get multiple system identifiers for a more unique HWID
            system_info = {
                'node': platform.node(),
                'machine': platform.machine(),
                'processor': platform.processor(),
                'system': platform.system(),
                'version': platform.version()
            }
            
            # Create a unique hash from system information
            hwid_string = json.dumps(system_info, sort_keys=True)
            hasher = hashes.Hash(hashes.SHA256())
            hasher.update(hwid_string.encode())
            return base64.b64encode(hasher.finalize()).decode()
            
        except Exception as e:
            logger.error(f"Failed to get HWID: {e}")
            return None

    async def verify_hwid(self, hwid: str) -> bool:
        """Verify HWID with improved error handling and retry mechanism"""
        console.print(f"\n[cyan]Verifying HWID: {hwid}[/]")
        
        if not self.session:
            self.session = aiohttp.ClientSession()

        for attempt in range(self.MAX_RETRIES):
            try:
                # Add timestamp to headers
                headers = {
                    'Content-Type': 'application/json',
                    'X-Timestamp': str(int(time.time())),
                    'User-Agent': f'HWIDClient/{platform.system()}'
                }

                async with self.session.post(
                    self.API_URL,
                    json={'hwid': hwid},
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    data = await response.json()
                    
                    if response.status == 200:
                        if data.get('exists') and data.get('verified') and data.get('status') == 'active':
                            console.print("[green]✓ HWID verified successfully.[/]")
                            return True
                        else:
                            if not data.get('verified'):
                                console.print("[yellow]⚠ HWID is not verified yet.[/]")
                            elif data.get('status') != 'active':
                                console.print(f"[yellow]⚠ HWID status is: {data.get('status')}[/]")
                            return False
                    else:
                        error_msg = data.get('error', 'Unknown error')
                        console.print(f"[red]✗ HWID verification failed: {error_msg}[/]")
                        return False
                        
            except aiohttp.ClientError as e:
                if attempt < self.MAX_RETRIES - 1:
                    console.print(f"[yellow]Connection error, retrying... ({attempt + 1}/{self.MAX_RETRIES})[/]")
                    await asyncio.sleep(self.RETRY_DELAY)
                    continue
                console.print(f"[red]✗ Connection error: {e}[/]")
                return False
            except Exception as e:
                if attempt < self.MAX_RETRIES - 1:
                    console.print(f"[yellow]Error occurred, retrying... ({attempt + 1}/{self.MAX_RETRIES})[/]")
                    await asyncio.sleep(self.RETRY_DELAY)
                    continue
                console.print(f"[red]✗ Error during verification: {e}[/]")
                return False
        
        return False

    async def start_commits(self) -> None:
        """Start the commit process with progress tracking"""
        if not Path(".git").exists():
            os.system("git init")
            os.system(f'git config user.name "{self.settings.author_name}"')
            os.system(f'git config user.email "{self.settings.author_email}"')

        console.print("\n[cyan]Starting commits process...[/]")
        
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=console
            ) as progress:
                
                total_commits = self.settings.total_day * (
                    self.settings.commit_freq if not self.settings.variability 
                    else self.settings.commit_freq // 2
                )
                
                task = progress.add_task("[cyan]Creating commits...", total=total_commits)
                
                async with aiofiles.open("commit.txt", "w") as f:
                    pointer = 0
                    ctr = 1
                    now = datetime.now()

                    for day in range(self.settings.total_day):
                        daily_commits = self.settings.commit_freq
                        if self.settings.variability:
                            daily_commits = randint(0, self.settings.commit_freq + 1)

                        for _ in range(daily_commits):
                            commit_date = now - timedelta(days=pointer)
                            formatted_date = commit_date.strftime("%Y-%m-%d")
                            await f.write(f"commit #{ctr}: {formatted_date}\n")
                            
                            commit_msg = self.settings.commit_message_template.format(ctr)
                            os.system("git add .")
                            os.system(f'git commit --date="{formatted_date} 12:00:00" -m "{commit_msg}"')
                            
                            progress.update(task, advance=1)
                            ctr += 1

                        pointer += 1

                console.print("\n[green]Commits completed. Pushing to repository...[/]")
                os.system(f"git remote add origin {self.settings.repo_link}")
                os.system("git branch -M main")
                os.system("git push -u origin main -f")
                console.print("\n[green]✓ Commits process completed and pushed to repository.[/]")
                
        except Exception as e:
            console.print(f"\n[red]Error during commit process: {e}[/]")
        
        await self.prompt_return()

    async def update_settings(self) -> None:
        """Update and save settings with validation"""
        console.print("\n[cyan]--- Update Settings ---[/]")
        try:
            # Get and validate settings
            total_day = console.input("[green]Enter total days (e.g., 36600): [/]")
            if not total_day.isdigit() or int(total_day) <= 0:
                raise ValueError("Total days must be a positive number")
            self.settings.total_day = int(total_day)

            commit_freq = console.input("[green]Enter commits per day (e.g., 100): [/]")
            if not commit_freq.isdigit() or int(commit_freq) <= 0:
                raise ValueError("Commits per day must be a positive number")
            self.settings.commit_freq = int(commit_freq)

            self.settings.variability = console.input(
                "[green]Enable random commits? (yes/no): [/]"
            ).strip().lower() == "yes"

            repo_link = console.input(
                "[green]Enter repository URL (e.g., https://github.com/username/repo.git): [/]"
            ).strip()
            if not repo_link.endswith('.git'):
                raise ValueError("Repository URL must end with .git")
            self.settings.repo_link = repo_link

            self.save_settings()
            console.print("\n[green]Settings updated and saved successfully.[/]")
            
        except ValueError as e:
            console.print(f"[red]Invalid input: {e}[/]")
        except Exception as e:
            console.print(f"[red]Error updating settings: {e}[/]")
        
        await self.prompt_return()

    def display_menu(self) -> None:
        """Display the main menu with rich formatting"""
        console.clear()
        console.print(Panel(
            "[cyan]1.[/] Start Commits\n"
            "[cyan]2.[/] Update Settings\n"
            "[cyan]3.[/] View Current Settings\n"
            "[cyan]4.[/] Reset Temporary Files\n"
            "[cyan]5.[/] Exit",
            title="[bold green]MAIN MENU[/]",
            subtitle="[italic]Created by PG Mohd Azhan Fikri[/]",
            border_style="cyan"
        ))

    async def view_settings(self) -> None:
        """Display current settings with rich formatting"""
        console.print("\n[cyan]--- Current Settings ---[/]")
        settings_table = Table(show_header=True, header_style="bold magenta")
        settings_table.add_column("Setting", style="cyan")
        settings_table.add_column("Value", style="green")
        
        for field, value in asdict(self.settings).items():
            settings_table.add_row(
                field.replace('_', ' ').title(),
                str(value)
            )
            
        console.print(settings_table)
        await self.prompt_return()

    async def reset_temporary_files(self) -> None:
        """Reset temporary files with confirmation"""
        try:
            if Path("commit.txt").exists():
                if console.input(
                    "[yellow]Are you sure you want to reset temporary files? (yes/no): [/]"
                ).lower() == 'yes':
                    Path("commit.txt").unlink()
                    console.print("\n[green]✓ Temporary files have been reset.[/]")
                else:
                    console.print("\n[yellow]Reset cancelled.[/]")
            else:
                console.print("\n[yellow]⚠ No temporary files found.[/]")
        except Exception as e:
            console.print(f"\n[red]Error resetting files: {e}[/]")
            
        await self.prompt_return()

    async def prompt_return(self) -> None:
        """Prompt user to return to main menu"""
        await asyncio.sleep(0.5)  # Small delay for better UX
        console.input("\n[cyan]Press Enter to return to the main menu...[/]")

    async def run(self) -> None:
        """Main program loop with improved error handling"""
        try:
            hwid = await self.get_hwid()
            if not hwid:
                return
            
            if not await self.verify_hwid(hwid):
                console.print("[red]Exiting program due to HWID verification failure.[/]")
                await asyncio.sleep(2)
                return

            while True:
                try:
                    self.display_menu()
                    choice = console.input("[green]Choose an option (1-5): [/]")

                    if choice == "1":
                        await self.start_commits()
                    elif choice == "2":
                        await self.update_settings()
                    elif choice == "3":
                        await self.view_settings()
                    elif choice == "4":
                        await self.reset_temporary_files()
                    elif choice == "5":
                        console.print("\n[green]Thank you for using the program. Goodbye![/]")
                        break
                    else:
                        console.print("\n[red]Invalid choice. Please select between 1 and 5.[/]")
                        await asyncio.sleep(1)
                except KeyboardInterrupt:
                    console.print("\n\n[yellow]Program interrupted by user.[/]")
                    break
                except Exception as e:
                    console.print(f"\n[red]An unexpected error occurred: {e}[/]")
                    await asyncio.sleep(2)
                    
        except Exception as e:
            console.print(f"[red]Critical error: {e}[/]")
        finally:
            if self.session:
                await self.session.close()