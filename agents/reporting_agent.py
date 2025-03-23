from typing import Dict, Any, List
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from .base_agent import BaseAgent, AgentState

class Report(BaseModel):
    timestamp: str
    vulnerabilities: List[Dict[str, Any]]
    exploit_attempts: List[Dict[str, Any]]
    patches: List[Dict[str, Any]]
    executive_summary: str
    technical_details: str
    recommendations: List[str]

class ReportingAgent(BaseAgent):
    def __init__(self):
        super().__init__("Reporting Agent", "security report generator")
        self.console = Console()
        
    async def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process all findings and generate comprehensive reports."""
        vulnerabilities = input_data.get("vulnerabilities", [])
        exploit_attempts = input_data.get("exploit_attempts", [])
        patches = input_data.get("patches", [])
        
        report = await self._generate_report(vulnerabilities, exploit_attempts, patches)
        
        self.update_state({
            "current_task": "report generation",
            "findings": {"report": report.dict()},
            "status": "completed"
        })
        
        return {
            "report": report.dict(),
            "formatted_report": await self._format_report(report)
        }
        
    async def _generate_report(self, vulnerabilities: List[Dict[str, Any]], 
                             exploit_attempts: List[Dict[str, Any]], 
                             patches: List[Dict[str, Any]]) -> Report:
        """Generate a comprehensive security report."""
        executive_summary = await self._generate_executive_summary(vulnerabilities, exploit_attempts, patches)
        technical_details = await self._generate_technical_details(vulnerabilities, exploit_attempts, patches)
        recommendations = await self._generate_recommendations(vulnerabilities, exploit_attempts, patches)
        
        return Report(
            timestamp=datetime.now().isoformat(),
            vulnerabilities=vulnerabilities,
            exploit_attempts=exploit_attempts,
            patches=patches,
            executive_summary=executive_summary,
            technical_details=technical_details,
            recommendations=recommendations
        )
        
    async def _generate_executive_summary(self, vulnerabilities: List[Dict[str, Any]], 
                                        exploit_attempts: List[Dict[str, Any]], 
                                        patches: List[Dict[str, Any]]) -> str:
        """Generate an executive summary of the security assessment."""
        critical_vulns = sum(1 for v in vulnerabilities if "Critical" in v["classification"]["analysis"])
        successful_exploits = sum(1 for e in exploit_attempts if e["success"])
        high_prob_patches = sum(1 for p in patches if p["success_probability"] >= 0.8)
        
        prompt = f"""
        Generate an executive summary for the security assessment with the following statistics:
        - Total vulnerabilities found: {len(vulnerabilities)}
        - Critical vulnerabilities: {critical_vulns}
        - Successfully exploited vulnerabilities: {successful_exploits}
        - High probability patches available: {high_prob_patches}
        
        Focus on:
        1. Overall security posture
        2. Key findings and risks
        3. Immediate actions required
        4. Long-term recommendations
        """
        
        return await self.communicate(prompt)
        
    async def _generate_technical_details(self, vulnerabilities: List[Dict[str, Any]], 
                                        exploit_attempts: List[Dict[str, Any]], 
                                        patches: List[Dict[str, Any]]) -> str:
        """Generate detailed technical information."""
        prompt = f"""
        Generate detailed technical information for the security assessment with:
        - {len(vulnerabilities)} vulnerabilities
        - {len(exploit_attempts)} exploit attempts
        - {len(patches)} patches
        
        Include:
        1. Vulnerability details and classifications
        2. Exploit attempt results and methodologies
        3. Patch descriptions and implementation steps
        4. Technical impact analysis
        """
        
        return await self.communicate(prompt)
        
    async def _generate_recommendations(self, vulnerabilities: List[Dict[str, Any]], 
                                      exploit_attempts: List[Dict[str, Any]], 
                                      patches: List[Dict[str, Any]]) -> List[str]:
        """Generate actionable recommendations."""
        prompt = f"""
        Generate actionable recommendations based on:
        - {len(vulnerabilities)} vulnerabilities
        - {len(exploit_attempts)} exploit attempts
        - {len(patches)} patches
        
        Provide specific, prioritized recommendations for:
        1. Immediate actions
        2. Short-term improvements
        3. Long-term security enhancements
        4. Process and policy updates
        """
        
        recommendations_text = await self.communicate(prompt)
        return [rec.strip() for rec in recommendations_text.split('\n') if rec.strip()]
        
    async def _format_report(self, report: Report) -> str:
        """Format the report using Rich for better readability."""
        # Create tables for different sections
        vuln_table = Table(title="Vulnerabilities")
        vuln_table.add_column("CVE ID")
        vuln_table.add_column("Severity")
        vuln_table.add_column("Status")
        
        for vuln in report.vulnerabilities:
            vuln_table.add_row(
                vuln["vulnerability"]["cve_id"],
                vuln["classification"]["analysis"].split("Severity level:")[1].split("\n")[0].strip(),
                "Patched" if any(p["vulnerability_id"] == vuln["vulnerability"]["cve_id"] for p in report.patches) else "Unpatched"
            )
            
        # Create the formatted report
        formatted_report = f"""
        {Panel.fit("Security Assessment Report", title="Executive Summary")}
        
        {report.executive_summary}
        
        {Panel.fit("Technical Details")}
        {report.technical_details}
        
        {Panel.fit("Vulnerabilities")}
        {vuln_table}
        
        {Panel.fit("Recommendations")}
        """
        
        for rec in report.recommendations:
            formatted_report += f"- {rec}\n"
            
        return formatted_report 