from typing import Dict, Any, List
from .base_agent import BaseAgent, AgentState
from pydantic import BaseModel

class ExploitAttempt(BaseModel):
    vulnerability_id: str
    success: bool
    details: str
    impact_level: str
    mitigation_suggestions: List[str]

class PenetrationAgent(BaseAgent):
    def __init__(self):
        super().__init__("Penetration Agent", "security penetration tester")
        self.exploit_attempts = []
        
    async def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process input data to perform penetration testing."""
        try:
            vulnerabilities = input_data.get("vulnerabilities", [])
            exploit_attempts = []
            
            for vuln in vulnerabilities:
                attempt = await self._attempt_exploit(vuln)
                if attempt:
                    exploit_attempts.append(attempt)
            
            self.update_state({
                "current_task": "penetration testing",
                "findings": exploit_attempts,
                "status": "completed"
            })
            
            return {
                "exploit_attempts": exploit_attempts,
                "summary": await self._generate_summary(exploit_attempts)
            }
        except Exception as e:
            self.update_state({
                "current_task": "penetration testing",
                "findings": [],
                "status": "error",
                "error": str(e)
            })
            return {
                "exploit_attempts": [],
                "summary": f"Error in penetration testing: {str(e)}"
            }
        
    async def _attempt_exploit(self, vulnerability: Dict[str, Any]) -> ExploitAttempt:
        """Attempt to exploit a specific vulnerability."""
        vuln_id = vulnerability.get("vulnerability_id", "unknown")
        description = vulnerability.get("description", "")
        vuln_type = vulnerability.get("vulnerability_type", "unknown")
        severity = vulnerability.get("severity", "Unknown")
        
        # Simulate exploit attempt based on vulnerability type and severity
        prompt = f"""
        Simulate an exploit attempt for the following vulnerability:
        ID: {vuln_id}
        Type: {vuln_type}
        Severity: {severity}
        Description: {description}
        
        Provide a detailed analysis of:
        1. Exploit success probability
        2. Required conditions for exploitation
        3. Potential impact if successful
        4. Suggested mitigation steps
        """
        
        analysis = await self.communicate(prompt)
        
        # More lenient success criteria for testing
        success = (
            severity.lower() in ["critical", "high"] or
            vuln_type.lower() in ["sql_injection", "authentication", "file_inclusion", "package", "service"] or
            "high probability" in analysis.lower() or
            "moderate probability" in analysis.lower()  # Added moderate probability
        )
        
        impact_level = "Critical" if success and severity.lower() in ["critical", "high"] else "Medium"
        
        return ExploitAttempt(
            vulnerability_id=vuln_id,
            success=success,
            details=analysis,
            impact_level=impact_level,
            mitigation_suggestions=self._extract_mitigation_suggestions(analysis)
        )
        
    def _extract_mitigation_suggestions(self, analysis: str) -> List[str]:
        """Extract mitigation suggestions from the analysis."""
        suggestions = []
        for line in analysis.split('\n'):
            if any(keyword in line.lower() for keyword in ["mitigation", "suggestion", "recommend", "should", "consider"]):
                suggestions.append(line.strip())
        return suggestions
        
    async def _generate_summary(self, exploit_attempts: List[ExploitAttempt]) -> str:
        """Generate a summary of penetration testing results."""
        successful_attempts = sum(1 for attempt in exploit_attempts if attempt.success)
        critical_impacts = sum(1 for attempt in exploit_attempts if attempt.impact_level == "Critical")
        
        summary = f"""
        Penetration Testing Summary:
        - Total vulnerabilities tested: {len(exploit_attempts)}
        - Successfully exploited: {successful_attempts}
        - Critical impact vulnerabilities: {critical_impacts}
        
        Detailed findings and mitigation suggestions have been documented for each vulnerability.
        """
        
        return summary 