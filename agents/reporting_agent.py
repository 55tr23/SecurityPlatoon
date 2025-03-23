from typing import Dict, Any, List
from datetime import datetime
from .base_agent import BaseAgent, AgentState
from rich.console import Console
from rich.table import Table
from pydantic import BaseModel
from rich.panel import Panel

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
        """Process input data to generate a comprehensive security report."""
        try:
            vulnerabilities = input_data.get("vulnerabilities", [])
            exploit_attempts = input_data.get("exploit_attempts", [])
            patches = input_data.get("patches", [])
            
            # Classify vulnerabilities by type and severity
            vuln_by_type = {}
            vuln_by_severity = {
                "Critical": 0,
                "High": 0,
                "Medium": 0,
                "Low": 0
            }
            
            for vuln in vulnerabilities:
                vuln_type = vuln.get("vulnerability_type", "unknown")
                severity = vuln.get("severity", "Low")
                
                if vuln_type not in vuln_by_type:
                    vuln_by_type[vuln_type] = 0
                vuln_by_type[vuln_type] += 1
                
                if severity in vuln_by_severity:
                    vuln_by_severity[severity] += 1
            
            # Generate executive summary
            executive_summary = await self._generate_executive_summary(
                vuln_by_type,
                vuln_by_severity,
                len(exploit_attempts),
                len(patches)
            )
            
            # Generate technical details
            technical_details = await self._generate_technical_details(
                vulnerabilities,
                exploit_attempts,
                patches
            )
            
            # Generate recommendations
            recommendations = await self._generate_recommendations(
                vulnerabilities,
                exploit_attempts,
                patches
            )
            
            # Create report
            report = {
                "executive_summary": executive_summary,
                "technical_details": technical_details,
                "recommendations": recommendations,
                "statistics": {
                    "vulnerabilities_by_type": vuln_by_type,
                    "vulnerabilities_by_severity": vuln_by_severity,
                    "exploit_attempts": len(exploit_attempts),
                    "patches": len(patches)
                }
            }
            
            self.update_state({
                "current_task": "report generation",
                "findings": [report],  # Convert to list for AgentState
                "status": "completed"
            })
            
            return report
        except Exception as e:
            self.update_state({
                "current_task": "report generation",
                "findings": [],  # Empty list for AgentState
                "status": "error",
                "error": str(e)
            })
            return {
                "executive_summary": f"Error in report generation: {str(e)}",
                "technical_details": "",
                "recommendations": []
            }
        
    async def _generate_executive_summary(
        self,
        vuln_by_type: Dict[str, int],
        vuln_by_severity: Dict[str, int],
        exploit_count: int,
        patch_count: int
    ) -> str:
        """Generate an executive summary of the security assessment."""
        total_vulns = sum(vuln_by_type.values())
        
        prompt = f"""
        Generate an executive summary for a security assessment with the following findings:
        
        Total Vulnerabilities: {total_vulns}
        By Type: {vuln_by_type}
        By Severity: {vuln_by_severity}
        Successful Exploit Attempts: {exploit_count}
        Patches Developed: {patch_count}
        
        Format the summary with these sections:
        1. Overall Security Posture
        2. Key Findings and Risks
        3. Immediate Actions Required
        4. Long-term Recommendations
        """
        
        return await self.communicate(prompt)
        
    async def _generate_technical_details(
        self,
        vulnerabilities: List[Dict[str, Any]],
        exploit_attempts: List[Dict[str, Any]],
        patches: List[Dict[str, Any]]
    ) -> str:
        """Generate technical details of the security assessment."""
        vuln_details = []
        for vuln in vulnerabilities:
            vuln_details.append(
                f"- {vuln.get('vulnerability_type', 'Unknown')} vulnerability: "
                f"{vuln.get('description', 'No description')} "
                f"(Severity: {vuln.get('severity', 'Unknown')})"
            )
            
        exploit_details = []
        for attempt in exploit_attempts:
            exploit_details.append(
                f"- Exploit attempt on {attempt.get('vulnerability_id', 'Unknown')}: "
                f"{'Successful' if attempt.get('success', False) else 'Failed'} "
                f"(Impact: {attempt.get('impact_level', 'Unknown')})"
            )
            
        patch_details = []
        for patch in patches:
            patch_details.append(
                f"- Patch for {patch.get('vulnerability_id', 'Unknown')}: "
                f"{patch.get('description', 'No description')} "
                f"(Status: {patch.get('status', 'Unknown')})"
            )
            
        prompt = f"""
        Generate technical details for the security assessment with:
        
        Vulnerability Details:
        {chr(10).join(vuln_details) if vuln_details else "No vulnerabilities found"}
        
        Exploit Attempts:
        {chr(10).join(exploit_details) if exploit_details else "No exploit attempts"}
        
        Patches:
        {chr(10).join(patch_details) if patch_details else "No patches required"}
        
        Include:
        1. Detailed analysis of each vulnerability type
        2. Impact assessment
        3. Technical recommendations
        """
        
        return await self.communicate(prompt)
        
    async def _generate_recommendations(
        self,
        vulnerabilities: List[Dict[str, Any]],
        exploit_attempts: List[Dict[str, Any]],
        patches: List[Dict[str, Any]]
    ) -> List[str]:
        """Generate recommendations based on the assessment findings."""
        vuln_types = set(v.get("vulnerability_type", "unknown") for v in vulnerabilities)
        severities = set(v.get("severity", "Low") for v in vulnerabilities)
        successful_exploits = sum(1 for a in exploit_attempts if a.get("success", False))
        
        prompt = f"""
        Generate specific recommendations based on:
        
        Vulnerability Types: {', '.join(vuln_types)}
        Severity Levels: {', '.join(severities)}
        Successful Exploits: {successful_exploits}
        Patches Required: {len(patches)}
        
        Provide recommendations for:
        1. Immediate actions (next 24-48 hours)
        2. Short-term improvements (1-4 weeks)
        3. Long-term security enhancements (1-6 months)
        4. Process and policy updates
        
        Format each recommendation as a bullet point starting with a dash (-)
        """
        
        recommendations = await self.communicate(prompt)
        return [rec.strip() for rec in recommendations.split('\n') if rec.strip().startswith('-')]
        
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