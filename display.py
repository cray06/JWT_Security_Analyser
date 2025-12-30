from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.json import JSON
import json

console = Console()

def print_analysis(data):
    header = data.get("header", {})
    payload = data.get("payload", {})
    results = data.get("results", [])

    console.print(Panel("[bold blue]JWT Security Analyzer[/bold blue]", expand=False))

    grid = Table.grid(expand=True)
    grid.add_column()
    grid.add_column()
    
    grid.add_row(
        Panel(JSON(json.dumps(header)), title="[bold]Header[/bold]", border_style="cyan"),
        Panel(JSON(json.dumps(payload)), title="[bold]Payload[/bold]", border_style="green")
    )
    console.print(grid)

    if not results:
        console.print(Panel("[bold green]No Obvious Issues Found[/bold green]", border_style="green"))
    else:
        for res in results:
            color = "red" if res["type"] == "Critical" else "yellow" if res["type"] == "High" else "blue"
            
            content = f"[bold]{res['msg']}[/bold]\n"
            content += f"[bold]Risk:[/bold] {res['risk']}\n"
            content += f"[bold]Fix:[/bold] {res['fix']}"
            
            console.print(Panel(content, title=f"[{color}]{res['type']}[/{color}]", border_style=color))
