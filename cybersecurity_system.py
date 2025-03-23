from typing import Dict, Any, List, Tuple
from langgraph.graph import Graph, StateGraph
from langgraph.prebuilt import ToolExecutor
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
        
        # Create the workflow graph
        workflow = StateGraph(StateType=Dict[str, Any])
        
        # Add nodes for each agent
        workflow.add_node("threat_analysis", self._run_threat_analysis)
        workflow.add_node("penetration_testing", self._run_penetration_testing)
        workflow.add_node("patch_development", self._run_patch_development)
        workflow.add_node("report_generation", self._run_report_generation)
        
        # Define the edges and flow
        workflow.add_edge("threat_analysis", "penetration_testing")
        workflow.add_edge("penetration_testing", "patch_development")
        workflow.add_edge("patch_development", "report_generation")
        
        # Set the entry point
        workflow.set_entry_point("threat_analysis")
        
        # Compile the graph
        chain = workflow.compile()
        
        # Run the workflow
        initial_state = {"system_info": system_info}
        final_state = await chain.ainvoke(initial_state)
        
        return final_state
        
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