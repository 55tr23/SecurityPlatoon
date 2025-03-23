from typing import Dict, Any, List, Tuple
from agents.threat_analysis_agent import ThreatAnalysisAgent
from agents.penetration_agent import PenetrationAgent
from agents.patching_agent import PatchingAgent
from agents.reporting_agent import ReportingAgent
import asyncio
from rich.console import Console

class CybersecuritySystem:
    def __init__(self):
        self.console = Console()
        self.threat_agent = ThreatAnalysisAgent()
        self.penetration_agent = PenetrationAgent()
        self.patching_agent = PatchingAgent()
        self.reporting_agent = ReportingAgent()
        
    async def analyze_system(self, system_info: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a system for vulnerabilities and generate a comprehensive report."""
        self.console.print("[bold blue]Starting Cybersecurity Analysis[/bold blue]")
        
        # Initialize state
        state = {"system_info": system_info}
        
        # Run each phase in sequence
        state = await self._run_threat_analysis(state)
        state = await self._run_penetration_testing(state)
        state = await self._run_patch_development(state)
        state = await self._run_report_generation(state)
        
        return state
        
    async def _run_threat_analysis(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Run the threat analysis phase."""
        self.console.print("[bold green]Running Threat Analysis[/bold green]")
        result = await self.threat_agent.process(state)
        return {**state, **result}
        
    async def _run_penetration_testing(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Run the penetration testing phase."""
        self.console.print("[bold yellow]Running Penetration Testing[/bold yellow]")
        result = await self.penetration_agent.process(state)
        return {**state, **result}
        
    async def _run_patch_development(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Run the patch development phase."""
        self.console.print("[bold magenta]Developing Patches[/bold magenta]")
        result = await self.patching_agent.process(state)
        return {**state, **result}
        
    async def _run_report_generation(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Run the report generation phase."""
        self.console.print("[bold cyan]Generating Report[/bold cyan]")
        result = await self.reporting_agent.process(state)
        return {**state, **result}

async def main():
    # Example usage
    system = CybersecuritySystem()
    
    # Example system information
    system_info = {
        "os_name": "Ubuntu",
        "os_version": "22.04 LTS",
        "kernel_version": "5.15.0-91-generic",
        "installed_packages": [
            "nginx",
            "postgresql",
            "python3",
            "docker"
        ],
        "network_services": [
            "ssh",
            "http",
            "https",
            "postgresql"
        ]
    }
    
    try:
        results = await system.analyze_system(system_info)
        
        # Print the formatted report
        console = Console()
        console.print(results["formatted_report"])
        
    except Exception as e:
        console = Console()
        console.print(f"[bold red]Error during analysis: {str(e)}[/bold red]")

if __name__ == "__main__":
    asyncio.run(main()) 