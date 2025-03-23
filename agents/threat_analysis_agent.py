from typing import Dict, Any, List
import requests
from bs4 import BeautifulSoup
from pydantic import BaseModel
from .base_agent import BaseAgent, AgentState
import re
import json
from datetime import datetime

class Vulnerability(BaseModel):
    cve_id: str
    description: str
    severity: str
    exploitability: str
    source: str
    references: List[str]
    vulnerability_type: str
    affected_components: List[str]
    detection_method: str
    mitigation_status: str = "Not Mitigated"
    discovery_date: str = ""
    last_modified: str = ""

class VulnerabilityType(BaseModel):
    name: str
    description: str
    detection_methods: List[str]
    common_indicators: List[str]
    mitigation_strategies: List[str]

class ThreatAnalysisAgent(BaseAgent):
    def __init__(self):
        super().__init__("Threat Analysis Agent", "security vulnerability analyst")
        self.databases = {
            "nvd": "https://nvd.nist.gov/vuln/data-feeds",
            "cisa": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "cve": "https://cve.mitre.org/data/downloads/index.html"
        }
        self.vulnerability_types = {
            "sql_injection": VulnerabilityType(
                name="SQL Injection",
                description="Vulnerability that allows attackers to manipulate database queries",
                detection_methods=["Input validation testing", "SQL query analysis", "Database monitoring"],
                common_indicators=["Unusual database queries", "Error messages containing SQL syntax", "Unexpected data in database"],
                mitigation_strategies=["Parameterized queries", "Input validation", "WAF implementation"]
            ),
            "xss": VulnerabilityType(
                name="Cross-Site Scripting (XSS)",
                description="Vulnerability that allows attackers to inject malicious scripts",
                detection_methods=["Input validation testing", "Output encoding analysis", "Browser security testing"],
                common_indicators=["Malicious script execution", "Unsanitized user input", "Browser security warnings"],
                mitigation_strategies=["Input sanitization", "Output encoding", "CSP implementation"]
            ),
            "csrf": VulnerabilityType(
                name="Cross-Site Request Forgery (CSRF)",
                description="Vulnerability that allows attackers to perform actions on behalf of users",
                detection_methods=["Token validation testing", "Request origin analysis", "Session management review"],
                common_indicators=["Unauthorized actions", "Missing CSRF tokens", "Incorrect request origins"],
                mitigation_strategies=["CSRF tokens", "SameSite cookies", "Request origin validation"]
            ),
            "file_inclusion": VulnerabilityType(
                name="File Inclusion",
                description="Vulnerability that allows attackers to include unauthorized files",
                detection_methods=["Path traversal testing", "File access analysis", "Input validation review"],
                common_indicators=["Unauthorized file access", "Directory traversal attempts", "File system errors"],
                mitigation_strategies=["Input validation", "File access controls", "Secure file handling"]
            ),
            "authentication": VulnerabilityType(
                name="Authentication Bypass",
                description="Vulnerability that allows unauthorized access to protected resources",
                detection_methods=["Authentication flow testing", "Session management analysis", "Access control review"],
                common_indicators=["Unauthorized access", "Session fixation", "Weak password policies"],
                mitigation_strategies=["Strong authentication", "Session management", "Access control implementation"]
            )
        }
        
    async def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process input data to identify vulnerabilities."""
        os_info = input_data.get("os_info", {})
        installed_packages = input_data.get("installed_packages", [])
        network_services = input_data.get("network_services", [])
        
        # Perform comprehensive scanning
        vulnerabilities = await self._scan_databases(os_info)
        package_vulns = await self._scan_packages(installed_packages)
        service_vulns = await self._scan_services(network_services)
        
        # Combine all vulnerabilities
        all_vulnerabilities = vulnerabilities + package_vulns + service_vulns
        
        # Classify and analyze vulnerabilities
        classified_vulns = await self._classify_vulnerabilities(all_vulnerabilities)
        
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
        
        for db_name, url in self.databases.items():
            try:
                vulns = await self._query_database(db_name, os_info)
                vulnerabilities.extend(vulns)
            except Exception as e:
                await self.communicate(f"Error scanning {db_name}: {str(e)}")
                
        return vulnerabilities
        
    async def _scan_packages(self, installed_packages: List[str]) -> List[Vulnerability]:
        """Scan installed packages for known vulnerabilities."""
        vulnerabilities = []
        
        for package in installed_packages:
            try:
                vulns = await self._query_package_vulnerabilities(package)
                vulnerabilities.extend(vulns)
            except Exception as e:
                await self.communicate(f"Error scanning package {package}: {str(e)}")
                
        return vulnerabilities
        
    async def _scan_services(self, network_services: List[str]) -> List[Vulnerability]:
        """Scan network services for vulnerabilities."""
        vulnerabilities = []
        
        for service in network_services:
            try:
                vulns = await self._query_service_vulnerabilities(service)
                vulnerabilities.extend(vulns)
            except Exception as e:
                await self.communicate(f"Error scanning service {service}: {str(e)}")
                
        return vulnerabilities
        
    async def _query_database(self, db_name: str, os_info: Dict[str, Any]) -> List[Vulnerability]:
        """Query a specific vulnerability database."""
        # This is a placeholder implementation
        # In production, you would implement actual API calls to each database
        prompt = f"""
        Query the {db_name} database for vulnerabilities related to:
        OS: {os_info.get('os_name', 'Unknown')}
        Version: {os_info.get('os_version', 'Unknown')}
        Kernel: {os_info.get('kernel_version', 'Unknown')}
        
        Return a list of relevant vulnerabilities with their details.
        """
        
        response = await self.communicate(prompt)
        return self._parse_vulnerability_response(response)
        
    async def _query_package_vulnerabilities(self, package: str) -> List[Vulnerability]:
        """Query vulnerabilities for a specific package."""
        prompt = f"""
        Analyze the package {package} for known vulnerabilities.
        Consider:
        1. Known CVEs
        2. Dependency vulnerabilities
        3. Configuration issues
        4. Version-specific vulnerabilities
        
        Return a list of relevant vulnerabilities with their details.
        """
        
        response = await self.communicate(prompt)
        return self._parse_vulnerability_response(response)
        
    async def _query_service_vulnerabilities(self, service: str) -> List[Vulnerability]:
        """Query vulnerabilities for a specific network service."""
        prompt = f"""
        Analyze the network service {service} for known vulnerabilities.
        Consider:
        1. Protocol vulnerabilities
        2. Configuration issues
        3. Authentication/Authorization weaknesses
        4. Common attack vectors
        
        Return a list of relevant vulnerabilities with their details.
        """
        
        response = await self.communicate(prompt)
        return self._parse_vulnerability_response(response)
        
    def _parse_vulnerability_response(self, response: str) -> List[Vulnerability]:
        """Parse the AI response into structured vulnerability data."""
        # This is a simplified implementation
        # In production, you would use more sophisticated parsing
        vulnerabilities = []
        
        # Extract CVE IDs
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        cve_ids = re.findall(cve_pattern, response)
        
        for cve_id in cve_ids:
            # Extract description
            desc_pattern = f"{cve_id}.*?(?={cve_pattern}|$)"
            desc_match = re.search(desc_pattern, response, re.DOTALL)
            description = desc_match.group(0).strip() if desc_match else "No description available"
            
            # Determine vulnerability type
            vuln_type = self._determine_vulnerability_type(description)
            
            # Create vulnerability object
            vuln = Vulnerability(
                cve_id=cve_id,
                description=description,
                severity=self._assess_severity(description),
                exploitability=self._assess_exploitability(description),
                source="AI Analysis",
                references=[f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
                vulnerability_type=vuln_type,
                affected_components=self._extract_affected_components(description),
                detection_method=self._select_detection_method(vuln_type),
                discovery_date=datetime.now().strftime("%Y-%m-%d")
            )
            vulnerabilities.append(vuln)
            
        return vulnerabilities
        
    def _determine_vulnerability_type(self, description: str) -> str:
        """Determine the type of vulnerability based on its description."""
        for vuln_type, details in self.vulnerability_types.items():
            if any(indicator.lower() in description.lower() for indicator in details.common_indicators):
                return vuln_type
        return "unknown"
        
    def _assess_severity(self, description: str) -> str:
        """Assess the severity of a vulnerability."""
        severity_keywords = {
            "critical": ["critical", "severe", "remote code execution", "privilege escalation"],
            "high": ["high", "significant", "data breach", "unauthorized access"],
            "medium": ["medium", "moderate", "information disclosure", "denial of service"],
            "low": ["low", "minor", "information gathering", "configuration"]
        }
        
        for severity, keywords in severity_keywords.items():
            if any(keyword in description.lower() for keyword in keywords):
                return severity.capitalize()
        return "Unknown"
        
    def _assess_exploitability(self, description: str) -> str:
        """Assess the exploitability of a vulnerability."""
        exploit_keywords = {
            "easy": ["easy to exploit", "trivial", "public exploit", "automated tools"],
            "moderate": ["moderate", "requires some skill", "manual steps", "configuration"],
            "difficult": ["difficult", "complex", "requires specific conditions", "rare"]
        }
        
        for level, keywords in exploit_keywords.items():
            if any(keyword in description.lower() for keyword in keywords):
                return level.capitalize()
        return "Unknown"
        
    def _extract_affected_components(self, description: str) -> List[str]:
        """Extract affected components from the vulnerability description."""
        components = []
        # Look for common component indicators
        component_patterns = [
            r'(?:in|of|for|affecting)\s+([A-Za-z0-9\s]+?)(?:\s+version|\s+component|\s+module)',
            r'([A-Za-z0-9\s]+?)\s+(?:vulnerability|issue|bug)'
        ]
        
        for pattern in component_patterns:
            matches = re.findall(pattern, description)
            components.extend(matches)
            
        return list(set(components))  # Remove duplicates
        
    def _select_detection_method(self, vuln_type: str) -> str:
        """Select appropriate detection method based on vulnerability type."""
        if vuln_type in self.vulnerability_types:
            return ", ".join(self.vulnerability_types[vuln_type].detection_methods)
        return "General vulnerability scanning"
        
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
        Type: {vulnerability.vulnerability_type}
        Severity: {vulnerability.severity}
        Exploitability: {vulnerability.exploitability}
        Affected Components: {', '.join(vulnerability.affected_components)}
        Detection Method: {vulnerability.detection_method}
        
        Provide a detailed analysis of:
        1. Severity level (Critical, High, Medium, Low)
        2. Exploitability (Easy, Moderate, Difficult)
        3. Potential impact
        4. Recommended priority for patching
        5. Specific mitigation strategies
        6. Detection and monitoring recommendations
        """
        
        analysis = await self.communicate(prompt)
        return {"analysis": analysis}
        
    async def _generate_summary(self, classified_vulns: List[Dict[str, Any]]) -> str:
        """Generate a human-readable summary of findings."""
        critical_count = sum(1 for v in classified_vulns if v["vulnerability"]["severity"] == "Critical")
        high_count = sum(1 for v in classified_vulns if v["vulnerability"]["severity"] == "High")
        medium_count = sum(1 for v in classified_vulns if v["vulnerability"]["severity"] == "Medium")
        low_count = sum(1 for v in classified_vulns if v["vulnerability"]["severity"] == "Low")
        
        # Group vulnerabilities by type
        vuln_types = {}
        for v in classified_vulns:
            vuln_type = v["vulnerability"]["vulnerability_type"]
            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = 0
            vuln_types[vuln_type] += 1
        
        summary = f"""
        Vulnerability Analysis Summary:
        - Total vulnerabilities found: {len(classified_vulns)}
        - Critical vulnerabilities: {critical_count}
        - High severity vulnerabilities: {high_count}
        - Medium severity vulnerabilities: {medium_count}
        - Low severity vulnerabilities: {low_count}
        
        Vulnerability Types:
        {chr(10).join(f"- {vuln_type}: {count}" for vuln_type, count in vuln_types.items())}
        
        Sources scanned:
        - Security databases: {', '.join(self.databases.keys())}
        - Installed packages
        - Network services
        
        Detailed findings have been classified and prioritized for further analysis.
        """
        
        return summary 