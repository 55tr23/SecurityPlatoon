from typing import Dict, Any, List, Tuple, TypedDict, Annotated
from agents.threat_analysis_agent import ThreatAnalysisAgent
from agents.penetration_agent import PenetrationAgent
from agents.patching_agent import PatchingAgent
from agents.reporting_agent import ReportingAgent
import asyncio
from rich.console import Console
from langgraph.graph import StateGraph, END

# Define the state schema
class AgentState(TypedDict):
    os_info: Dict[str, str]
    installed_packages: List[str]
    network_services: List[str]
    vulnerabilities: List[Dict[str, Any]]
    exploit_attempts: List[Dict[str, Any]]
    patches: List[Dict[str, Any]]
    report: Dict[str, Any]
    current_agent: str
    error: str | None

class CybersecuritySystem:
    def __init__(self):
        self.console = Console()
        self.threat_agent = ThreatAnalysisAgent()
        self.penetration_agent = PenetrationAgent()
        self.patching_agent = PatchingAgent()
        self.reporting_agent = ReportingAgent()
        
        # Create the graph
        self.workflow = self._create_workflow()
        
    def _create_workflow(self) -> StateGraph:
        """Create the LangGraph workflow."""
        # Create a state graph
        workflow = StateGraph(AgentState)
        
        # Add nodes for each agent
        workflow.add_node("threat_analysis", self._run_threat_analysis)
        workflow.add_node("penetration_testing", self._run_penetration_testing)
        workflow.add_node("patch_development", self._run_patch_development)
        workflow.add_node("report_generation", self._run_report_generation)
        
        # Define the edges (flow)
        workflow.add_edge("threat_analysis", "penetration_testing")
        workflow.add_edge("penetration_testing", "patch_development")
        workflow.add_edge("patch_development", "report_generation")
        workflow.add_edge("report_generation", END)
        
        # Set the entry point
        workflow.set_entry_point("threat_analysis")
        
        # Compile the graph
        return workflow.compile()
        
    async def _run_threat_analysis(self, state: AgentState) -> AgentState:
        """Run threat analysis agent."""
        self.console.print("[bold cyan]Running Threat Analysis[/bold cyan]")
        try:
            results = await self.threat_agent.process({
                "os_info": state["os_info"],
                "installed_packages": state["installed_packages"],
                "network_services": state["network_services"]
            })
            
            state["vulnerabilities"] = results.get("vulnerabilities", [])
            state["current_agent"] = "threat_analysis"
            if not state["vulnerabilities"]:
                self.console.print("[yellow]No vulnerabilities found during threat analysis[/yellow]")
            
            return state
        except Exception as e:
            state["error"] = f"Error in threat analysis: {str(e)}"
            self.console.print(f"[red]Error in threat analysis: {str(e)}[/red]")
            return state
            
    async def _run_penetration_testing(self, state: AgentState) -> AgentState:
        """Run penetration testing agent."""
        self.console.print("[bold cyan]Running Penetration Testing[/bold cyan]")
        try:
            results = await self.penetration_agent.process({
                "vulnerabilities": state["vulnerabilities"]
            })
            
            state["exploit_attempts"] = results.get("exploit_attempts", [])
            state["current_agent"] = "penetration_testing"
            if not state["exploit_attempts"]:
                self.console.print("[yellow]No successful exploit attempts[/yellow]")
            
            return state
        except Exception as e:
            state["error"] = f"Error in penetration testing: {str(e)}"
            self.console.print(f"[red]Error in penetration testing: {str(e)}[/red]")
            return state
            
    async def _run_patch_development(self, state: AgentState) -> AgentState:
        """Run patch development agent."""
        self.console.print("[bold cyan]Developing and Applying Patches[/bold cyan]")
        try:
            results = await self.patching_agent.process({
                "vulnerabilities": state["vulnerabilities"],
                "exploit_attempts": state["exploit_attempts"]
            })
            
            state["patches"] = results.get("patches", [])
            state["current_agent"] = "patch_development"
            if not state["patches"]:
                self.console.print("[yellow]No patches required[/yellow]")
            
            return state
        except Exception as e:
            state["error"] = f"Error in patch development: {str(e)}"
            self.console.print(f"[red]Error in patch development: {str(e)}[/red]")
            return state
            
    async def _run_report_generation(self, state: AgentState) -> AgentState:
        """Run report generation agent."""
        self.console.print("[bold cyan]Generating Report[/bold cyan]")
        try:
            report = await self.reporting_agent.process({
                "vulnerabilities": state["vulnerabilities"],
                "exploit_attempts": state["exploit_attempts"],
                "patches": state["patches"],
                "os_info": state["os_info"],
                "installed_packages": state["installed_packages"],
                "network_services": state["network_services"]
            })
            
            state["report"] = report
            state["current_agent"] = "report_generation"
            return state
        except Exception as e:
            state["error"] = f"Error in report generation: {str(e)}"
            self.console.print(f"[red]Error in report generation: {str(e)}[/red]")
            return state
            
    async def analyze_system(self, os_info: Dict[str, str], installed_packages: List[str], network_services: List[str]) -> Dict[str, Any]:
        """Analyze a system for vulnerabilities using the LangGraph workflow."""
        try:
            self.console.print("[bold green]Starting Cybersecurity Analysis[/bold green]")
            
            # Initialize the state
            initial_state: AgentState = {
                "os_info": os_info,
                "installed_packages": installed_packages,
                "network_services": network_services,
                "vulnerabilities": [],
                "exploit_attempts": [],
                "patches": [],
                "report": {},
                "current_agent": "",
                "error": None
            }
            
            # Run the workflow
            final_state = await self.workflow.ainvoke(initial_state)
            
            if final_state["error"]:
                raise Exception(final_state["error"])
                
            return {
                "vulnerabilities": final_state["vulnerabilities"],
                "exploit_attempts": final_state["exploit_attempts"],
                "patches": final_state["patches"],
                "report": final_state["report"]
            }
        except Exception as e:
            self.console.print(f"[bold red]Error during analysis: {str(e)}[/bold red]")
            return {
                "vulnerabilities": [],
                "exploit_attempts": [],
                "patches": [],
                "report": {
                    "executive_summary": "Error during analysis",
                    "technical_details": str(e),
                    "recommendations": []
                }
            }

async def main():
    # Example usage
    system = CybersecuritySystem()
    
    # Example system information
    system_info = {
        "os_name": "Ubuntu",
        "os_version": "22.04 LTS",
        "kernel_version": "5.15.0-91-generic"
    }
    
    installed_packages = [
        "nginx",
        "postgresql",
        "python3",
        "docker"
    ]
    
    network_services = [
        "ssh",
        "http",
        "https",
        "postgresql"
    ]
    
    try:
        results = await system.analyze_system(
            system_info,
            installed_packages,
            network_services
        )
        
        # Print the formatted report
        console = Console()
        console.print(results["report"]["executive_summary"])
        
    except Exception as e:
        console = Console()
        console.print(f"[bold red]Error during analysis: {str(e)}[/bold red]")

if __name__ == "__main__":
    asyncio.run(main()) 