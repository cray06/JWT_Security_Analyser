import typer
from core import analyze_token
from display import print_analysis
import sys

app = typer.Typer(add_completion=False)

@app.command()
def main(
    token: str = typer.Argument(..., help="The JWT Token to analyze"),
    secret: str = typer.Option(None, help="The HMAC secret key to verify signature"),
    public_key: str = typer.Option(None, help="Path to Public Key file for verification"),
    bruteforce: bool = typer.Option(False, help="Attempt to brute-force HS256 secret"),
    wordlist: str = typer.Option(None, help="Path to custom wordlist for brute-force")
):
    if not token:
        typer.echo("Error: No token provided")
        raise typer.Exit(code=1)
        
    pk_content = None
    if public_key:
        try:
            with open(public_key, 'r') as f:
                pk_content = f.read()
        except Exception as e:
            typer.echo(f"Error reading public key: {e}")

    analysis = analyze_token(token, secret=secret, public_key=pk_content, bruteforce=bruteforce, wordlist=wordlist)
    
    if bruteforce:
        from rich.console import Console
        console = Console()
        bf_results = [r for r in analysis["results"] if "brute-force" in r["msg"].lower() or "weak secret" in r["msg"].lower()]
        
        for res in bf_results:
            if "Weak Secret" in res["msg"]:
                console.print(f"[bold green]SUCCESS:[/bold green] {res['msg']}")
            elif res["type"] == "Info" or "cannot be brute-forced" in res["msg"]:
                console.print(f"[bold blue]INFO:[/bold blue] {res['msg']}")
            else:
                console.print(f"[bold red]FAILED:[/bold red] {res['msg']}")
                console.print(f"Tip: {res['fix']}")
    else:
        print_analysis(analysis)

if __name__ == "__main__":
    app()
