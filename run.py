#!/usr/bin/env python3
import asyncio
from client import HWIDClient
from rich.console import Console

console = Console()

async def main():
    try:
        client = HWIDClient()
        await client.run()
    except Exception as e:
        console.print(f"[red]Failed to initialize client: {e}[/]")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Program terminated by user[/]")
    except Exception as e:
        console.print(f"[red]Fatal error: {e}[/]")