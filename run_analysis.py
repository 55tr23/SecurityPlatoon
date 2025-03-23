import asyncio
import platform
import os
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from dotenv import load_dotenv
from cybersecurity_system import CybersecuritySystem

async def main():
    """Run the cybersecurity analysis."""
    console = Console()
    
    try:
        # Load environment variables
        load_dotenv()
        if not os.getenv("OPENAI_API_KEY"):
            console.print("[red]Error: OPENAI_API_KEY not found in environment variables[/red]")
            return
            
        console.print("[green]Starting system analysis...[/green]")
        
        # Get system information
        os_info = {
            "os_name": platform.system(),
            "os_version": platform.version(),
            "kernel_version": platform.release()
        }
        
        # Example lists - modify as needed
        installed_packages = [
            "python 3.12.0",
            "pip 23.3.2",
            "setuptools 69.0.3",
            "wheel 0.42.0"
        ]
        
        network_services = [
            "HTTP (80)",
            "HTTPS (443)",
            "SSH (22)",
            "DNS (53)"
        ]
        
        # Initialize and run the cybersecurity system
        system = CybersecuritySystem()
        results = await system.analyze_system(
            os_info,
            installed_packages,
            network_services
        )
        
        # Display results in a formatted way
        console.print("\n[bold cyan]Analysis Results:[/bold cyan]\n")
        
        # Executive Summary
        if results["report"].get("executive_summary"):
            console.print(Panel(
                Text(results["report"]["executive_summary"], style="green"),
                title="Executive Summary",
                expand=True
            ))
        
        # Technical Details
        if results["report"].get("technical_details"):
            console.print(Panel(
                Text(results["report"]["technical_details"], style="blue"),
                title="Technical Details",
                expand=True
            ))
        
        # Create a table for vulnerabilities
        vuln_table = Table(title="Vulnerability Summary")
        vuln_table.add_column("Type", style="cyan")
        vuln_table.add_column("Count", style="magenta")
        vuln_table.add_column("Severity", style="red")
        
        if results.get("vulnerabilities"):
            for vuln in results["vulnerabilities"]:
                vuln_table.add_row(
                    str(vuln.get("vulnerability_type", "Unknown")),
                    "1",
                    str(vuln.get("severity", "Unknown"))
                )
        else:
            vuln_table.add_row("No vulnerabilities found", "-", "-")
            
        console.print(Panel(vuln_table))
        
        # Recommendations
        recommendations = results["report"].get("recommendations", [])
        if recommendations:
            if isinstance(recommendations, list):
                recommendations_text = "\n".join(f"- {rec}" for rec in recommendations)
            else:
                recommendations_text = str(recommendations)
                
            console.print(Panel(
                Text(recommendations_text, style="yellow"),
                title="Recommendations",
                expand=True
            ))
        
    except Exception as e:
        console.print(f"[red]Error during analysis: {str(e)}[/red]")

if __name__ == "__main__":
    asyncio.run(main()) 