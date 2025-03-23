from typing import Dict, Any, List
import requests
from bs4 import BeautifulSoup
from .base_agent import BaseAgent, AgentState

class Vulnerability(BaseModel):
    cve_id: str
    description: str
    severity: str
    exploitability: str
    source: str
    references: List[str]

class ThreatAnalysisAgent(BaseAgent):
    def __init__(self):
        super().__init__("Threat Analysis Agent", "security vulnerability analyst")
        self.databases = {
            "nvd": "https://nvd.nist.gov/vuln/data-feeds",
            "cisa": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "cve": "https://cve.mitre.org/data/downloads/index.html"
        }
        
    async def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process input data to identify vulnerabilities."""
        os_info = input_data.get("os_info", {})
        vulnerabilities = await self._scan_databases(os_info)
        classified_vulns = await self._classify_vulnerabilities(vulnerabilities)
        
        self.update_state({
            "current_task": "vulnerability analysis",
            "findings": classified_vulns,
            "status": "completed"
        })
        
        return {
            "vulnerabilities": classified_vulns,
            "summary": await self._generate_summary(classified_vulns)
        }
        
    async def _scan_databases(self, os_info: Dict[str, Any]) -> List[Vulnerability]:
        """Scan various security databases for vulnerabilities."""
        vulnerabilities = []
        
        # Example implementation - in production, you would implement proper API calls
        # and error handling for each database
        for db_name, url in self.databases.items():
            try:
                # This is a placeholder - implement actual API calls
                vulns = await self._query_database(db_name, os_info)
                vulnerabilities.extend(vulns)
            except Exception as e:
                await self.communicate(f"Error scanning {db_name}: {str(e)}")
                
        return vulnerabilities
        
    async def _classify_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> List[Dict[str, Any]]:
        """Classify vulnerabilities based on severity and exploitability."""
        classified = []
        
        for vuln in vulnerabilities:
            classification = await self._analyze_vulnerability(vuln)
            classified.append({
                "vulnerability": vuln.dict(),
                "classification": classification
            })
            
        return classified
        
    async def _analyze_vulnerability(self, vulnerability: Vulnerability) -> Dict[str, Any]:
        """Analyze a single vulnerability for severity and exploitability."""
        prompt = f"""
        Analyze the following vulnerability:
        CVE ID: {vulnerability.cve_id}
        Description: {vulnerability.description}
        Source: {vulnerability.source}
        
        Provide a detailed analysis of:
        1. Severity level (Critical, High, Medium, Low)
        2. Exploitability (Easy, Moderate, Difficult)
        3. Potential impact
        4. Recommended priority for patching
        """
        
        analysis = await self.communicate(prompt)
        return {"analysis": analysis}
        
    async def _generate_summary(self, classified_vulns: List[Dict[str, Any]]) -> str:
        """Generate a human-readable summary of findings."""
        critical_count = sum(1 for v in classified_vulns if "Critical" in v["classification"]["analysis"])
        high_count = sum(1 for v in classified_vulns if "High" in v["classification"]["analysis"])
        
        summary = f"""
        Vulnerability Analysis Summary:
        - Total vulnerabilities found: {len(classified_vulns)}
        - Critical vulnerabilities: {critical_count}
        - High severity vulnerabilities: {high_count}
        - Sources scanned: {', '.join(self.databases.keys())}
        
        Detailed findings have been classified and prioritized for further analysis.
        """
        
        return summary 