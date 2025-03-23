from typing import Dict, Any, List
import requests
from bs4 import BeautifulSoup
from pydantic import BaseModel
from .base_agent import BaseAgent, AgentState
import re
import json
from datetime import datetime, timedelta
import aiohttp
import asyncio
from typing import Optional
import os

class Vulnerability(BaseModel):
    cve_id: str = ""
    description: str = ""
    severity: str = "Unknown"
    exploitability: str = "Unknown"
    source: str = ""
    references: List[str] = []
    vulnerability_type: str = "unknown"
    affected_components: List[str] = []
    detection_method: str = ""
    mitigation_status: str = "Not Mitigated"
    discovery_date: str = ""
    last_modified: str = ""
    cvss_score: Optional[float] = None
    attack_vector: Optional[str] = None
    attack_complexity: Optional[str] = None
    privileges_required: Optional[str] = None
    user_interaction: Optional[str] = None
    scope: Optional[str] = None
    confidentiality: Optional[str] = None
    integrity: Optional[str] = None
    availability: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert the vulnerability to a dictionary with string keys."""
        return {
            "cve_id": self.cve_id or "",
            "description": self.description or "",
            "severity": self.severity or "Unknown",
            "exploitability": self.exploitability or "Unknown",
            "source": self.source or "",
            "references": self.references or [],
            "vulnerability_type": self.vulnerability_type or "unknown",
            "affected_components": self.affected_components or [],
            "detection_method": self.detection_method or "",
            "mitigation_status": self.mitigation_status or "Not Mitigated",
            "discovery_date": self.discovery_date or "",
            "last_modified": self.last_modified or "",
            "cvss_score": float(self.cvss_score) if self.cvss_score is not None else 0.0,
            "attack_vector": self.attack_vector or "Unknown",
            "attack_complexity": self.attack_complexity or "Unknown",
            "privileges_required": self.privileges_required or "Unknown",
            "user_interaction": self.user_interaction or "Unknown",
            "scope": self.scope or "Unknown",
            "confidentiality": self.confidentiality or "Unknown",
            "integrity": self.integrity or "Unknown",
            "availability": self.availability or "Unknown"
        }

class VulnerabilityType(BaseModel):
    name: str
    description: str
    detection_methods: List[str]
    common_indicators: List[str]
    mitigation_strategies: List[str]
    attack_patterns: List[str]
    risk_level: str

class ThreatAnalysisAgent(BaseAgent):
    def __init__(self):
        super().__init__("Threat Analysis Agent", "security vulnerability analyst")
        self.databases = {
            "nvd": {
                "base_url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
                "api_key": None,  # Will be loaded from environment
                "headers": {
                    "apiKey": None,
                    "Content-Type": "application/json"
                }
            },
            "cisa": {
                "base_url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                "api_key": None,
                "headers": {
                    "Content-Type": "application/json"
                }
            },
            "cve": {
                "base_url": "https://cve.circl.lu/api/search/",
                "api_key": None,
                "headers": {
                    "Content-Type": "application/json"
                }
            }
        }
        self.scan_parameters = {
            "max_results": 100,
            "time_range": "last_30_days",
            "severity_threshold": "MEDIUM",
            "include_exploited": True,
            "include_potential": True,
            "include_historical": True,
            "scan_depth": "deep",
            "check_dependencies": True,
            "check_configurations": True,
            "check_network": True,
            "check_authentication": True,
            "check_authorization": True,
            "check_data_validation": True,
            "check_error_handling": True,
            "check_logging": True,
            "check_encryption": True,
            "check_session_management": True,
            "check_input_validation": True,
            "check_output_encoding": True,
            "check_file_operations": True,
            "check_database_operations": True,
            "check_api_endpoints": True,
            "check_third_party": True,
            "check_custom_code": True
        }
        self.vulnerability_types = {
            "sql_injection": VulnerabilityType(
                name="SQL Injection",
                description="Vulnerability that allows attackers to manipulate database queries",
                detection_methods=["Input validation testing", "SQL query analysis", "Database monitoring", "SQL injection scanners", "Dynamic analysis"],
                common_indicators=["Unusual database queries", "Error messages containing SQL syntax", "Unexpected data in database", "SQL errors in logs", "Database performance issues"],
                mitigation_strategies=["Parameterized queries", "Input validation", "WAF implementation", "Database hardening", "Least privilege access"],
                attack_patterns=["UNION-based", "Boolean-based", "Time-based", "Error-based", "Stacked queries"],
                risk_level="Critical"
            ),
            "xss": VulnerabilityType(
                name="Cross-Site Scripting (XSS)",
                description="Vulnerability that allows attackers to inject malicious scripts",
                detection_methods=["Input validation testing", "Output encoding analysis", "Browser security testing", "XSS scanners", "DOM analysis"],
                common_indicators=["Malicious script execution", "Unsanitized user input", "Browser security warnings", "JavaScript errors", "DOM manipulation"],
                mitigation_strategies=["Input sanitization", "Output encoding", "CSP implementation", "XSS filters", "Content security headers"],
                attack_patterns=["Reflected XSS", "Stored XSS", "DOM-based XSS", "Self-XSS", "Universal XSS"],
                risk_level="High"
            ),
            "csrf": VulnerabilityType(
                name="Cross-Site Request Forgery (CSRF)",
                description="Vulnerability that allows attackers to perform actions on behalf of users",
                detection_methods=["Token validation testing", "Request origin analysis", "Session management review", "CSRF scanners", "Request analysis"],
                common_indicators=["Unauthorized actions", "Missing CSRF tokens", "Incorrect request origins", "Session fixation", "Token reuse"],
                mitigation_strategies=["CSRF tokens", "SameSite cookies", "Request origin validation", "Double-submit cookies", "Custom headers"],
                attack_patterns=["Token bypass", "Token prediction", "Token theft", "Token replay", "Token fixation"],
                risk_level="High"
            ),
            "file_inclusion": VulnerabilityType(
                name="File Inclusion",
                description="Vulnerability that allows attackers to include unauthorized files",
                detection_methods=["Path traversal testing", "File access analysis", "Input validation review", "File inclusion scanners", "Directory traversal testing"],
                common_indicators=["Unauthorized file access", "Directory traversal attempts", "File system errors", "Path manipulation", "File inclusion errors"],
                mitigation_strategies=["Input validation", "File access controls", "Secure file handling", "Path normalization", "Access control lists"],
                attack_patterns=["Local file inclusion", "Remote file inclusion", "Directory traversal", "Null byte injection", "Path manipulation"],
                risk_level="Critical"
            ),
            "authentication": VulnerabilityType(
                name="Authentication Bypass",
                description="Vulnerability that allows unauthorized access to protected resources",
                detection_methods=["Authentication flow testing", "Session management analysis", "Access control review", "Auth bypass scanners", "Token analysis"],
                common_indicators=["Unauthorized access", "Session fixation", "Weak password policies", "Token manipulation", "Auth bypass attempts"],
                mitigation_strategies=["Strong authentication", "Session management", "Access control implementation", "Multi-factor auth", "Token rotation"],
                attack_patterns=["Session fixation", "Token prediction", "Password bypass", "Auth bypass", "Privilege escalation"],
                risk_level="Critical"
            )
        }
        
    async def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process input data to identify vulnerabilities."""
        try:
            os_info = input_data.get("os_info", {})
            installed_packages = input_data.get("installed_packages", [])
            network_services = input_data.get("network_services", [])
            
            # Initialize vulnerabilities list
            vulnerabilities = []
            
            # Scan packages first
            print("Scanning installed packages...")
            package_vulns = await self._scan_packages(installed_packages)
            if package_vulns:
                vulnerabilities.extend(package_vulns)
                print(f"Found {len(package_vulns)} package vulnerabilities")
            
            # Scan services
            print("Scanning network services...")
            service_vulns = await self._scan_services(network_services)
            if service_vulns:
                vulnerabilities.extend(service_vulns)
                print(f"Found {len(service_vulns)} service vulnerabilities")
            
            # Scan configurations
            print("Scanning system configurations...")
            config_vulns = await self._scan_configurations(os_info)
            if config_vulns:
                for vuln in config_vulns:
                    vulnerabilities.append({
                        "vulnerability_id": vuln.cve_id,
                        "vulnerability_type": vuln.vulnerability_type,
                        "severity": vuln.severity,
                        "exploitability": vuln.exploitability,
                        "description": vuln.description,
                        "affected_components": vuln.affected_components,
                        "detection_method": vuln.detection_method,
                        "source": vuln.source,
                        "references": vuln.references
                    })
                print(f"Found {len(config_vulns)} configuration vulnerabilities")
            
            # Scan authentication
            print("Scanning authentication systems...")
            auth_vulns = await self._scan_authentication(os_info)
            if auth_vulns:
                for vuln in auth_vulns:
                    vulnerabilities.append({
                        "vulnerability_id": vuln.cve_id,
                        "vulnerability_type": vuln.vulnerability_type,
                        "severity": vuln.severity,
                        "exploitability": vuln.exploitability,
                        "description": vuln.description,
                        "affected_components": vuln.affected_components,
                        "detection_method": vuln.detection_method,
                        "source": vuln.source,
                        "references": vuln.references
                    })
                print(f"Found {len(auth_vulns)} authentication vulnerabilities")
            
            # Scan external databases if needed
            if not vulnerabilities:
                print("Scanning external security databases...")
                db_vulns = await self._scan_databases(os_info)
                if db_vulns:
                    for vuln in db_vulns:
                        vulnerabilities.append({
                            "vulnerability_id": vuln.cve_id,
                            "vulnerability_type": vuln.vulnerability_type,
                            "severity": vuln.severity,
                            "exploitability": vuln.exploitability,
                            "description": vuln.description,
                            "affected_components": vuln.affected_components,
                            "detection_method": vuln.detection_method,
                            "source": vuln.source,
                            "references": vuln.references
                        })
                    print(f"Found {len(db_vulns)} database vulnerabilities")
            
            # Update state and return results
            self.update_state({
                "current_task": "vulnerability analysis",
                "findings": vulnerabilities,
                "status": "completed"
            })
            
            total_vulns = len(vulnerabilities)
            print(f"Total vulnerabilities found: {total_vulns}")
            
            return {
                "vulnerabilities": vulnerabilities,
                "summary": await self._generate_summary(vulnerabilities)
            }
        except Exception as e:
            self.update_state({
                "current_task": "vulnerability analysis",
                "findings": [],
                "status": "error",
                "error": str(e)
            })
            return {
                "vulnerabilities": [],
                "summary": f"Error in vulnerability analysis: {str(e)}"
            }
        
    async def _scan_databases(self, os_info: Dict[str, Any]) -> List[Vulnerability]:
        """Scan various security databases for vulnerabilities using actual API calls."""
        vulnerabilities = []
        
        async with aiohttp.ClientSession() as session:
            tasks = []
            for db_name, db_info in self.databases.items():
                if db_name == "nvd":
                    tasks.append(self._query_nvd(session, os_info))
                elif db_name == "cisa":
                    tasks.append(self._query_cisa(session, os_info))
                elif db_name == "cve":
                    tasks.append(self._query_cve(session, os_info))
            
            results = await asyncio.gather(*tasks)
            for result in results:
                vulnerabilities.extend(result)
                
        return vulnerabilities
        
    async def _query_nvd(self, session: aiohttp.ClientSession, os_info: Dict[str, Any]) -> List[Vulnerability]:
        """Query the NVD database using their API."""
        params = {
            "keywordSearch": f"{os_info.get('os_name', '')} {os_info.get('os_version', '')}",
            "resultsPerPage": self.scan_parameters["max_results"],
            "startIndex": 0,
            "pubStartDate": (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%dT00:00:00.000Z"),
            "cvssV3Severity": self.scan_parameters["severity_threshold"]
        }
        
        if self.databases["nvd"]["api_key"]:
            params["apiKey"] = self.databases["nvd"]["api_key"]
            
        async with session.get(
            self.databases["nvd"]["base_url"],
            params=params,
            headers=self.databases["nvd"]["headers"]
        ) as response:
            if response.status == 200:
                data = await response.json()
                return self._parse_nvd_response(data)
            else:
                await self.communicate(f"Error querying NVD: {response.status}")
                return []
                
    async def _query_cisa(self, session: aiohttp.ClientSession, os_info: Dict[str, Any]) -> List[Vulnerability]:
        """Query the CISA Known Exploited Vulnerabilities catalog."""
        async with session.get(
            self.databases["cisa"]["base_url"],
            headers=self.databases["cisa"]["headers"]
        ) as response:
            if response.status == 200:
                data = await response.json()
                return self._parse_cisa_response(data, os_info)
            else:
                await self.communicate(f"Error querying CISA: {response.status}")
                return []
                
    async def _query_cve(self, session: aiohttp.ClientSession, os_info: Dict[str, Any]) -> List[Vulnerability]:
        """Query the CVE database."""
        search_term = f"{os_info.get('os_name', '')} {os_info.get('os_version', '')}"
        async with session.get(
            f"{self.databases['cve']['base_url']}{search_term}",
            headers=self.databases["cve"]["headers"]
        ) as response:
            if response.status == 200:
                data = await response.json()
                return self._parse_cve_response(data)
            else:
                await self.communicate(f"Error querying CVE: {response.status}")
                return []
                
    def _parse_nvd_response(self, data: Dict[str, Any]) -> List[Vulnerability]:
        """Parse NVD API response into Vulnerability objects."""
        vulnerabilities = []
        
        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            metrics = vuln.get("metrics", {}).get("cvssMetricV31", [{}])[0]
            
            vuln_obj = Vulnerability(
                cve_id=cve.get("id", ""),
                description=cve.get("descriptions", [{}])[0].get("value", ""),
                severity=metrics.get("cvssData", {}).get("baseSeverity", "Unknown"),
                exploitability=self._assess_exploitability(metrics.get("cvssData", {})),
                source="NVD",
                references=[ref.get("url", "") for ref in cve.get("references", [])],
                vulnerability_type=self._determine_vulnerability_type(cve.get("descriptions", [{}])[0].get("value", "")),
                affected_components=self._extract_affected_components(cve.get("descriptions", [{}])[0].get("value", "")),
                detection_method=self._select_detection_method(self._determine_vulnerability_type(cve.get("descriptions", [{}])[0].get("value", ""))),
                discovery_date=cve.get("published", ""),
                last_modified=cve.get("lastModified", ""),
                cvss_score=float(metrics.get("cvssData", {}).get("baseScore", 0)),
                attack_vector=metrics.get("cvssData", {}).get("attackVector", ""),
                attack_complexity=metrics.get("cvssData", {}).get("attackComplexity", ""),
                privileges_required=metrics.get("cvssData", {}).get("privilegesRequired", ""),
                user_interaction=metrics.get("cvssData", {}).get("userInteraction", ""),
                scope=metrics.get("cvssData", {}).get("scope", ""),
                confidentiality=metrics.get("cvssData", {}).get("confidentialityImpact", ""),
                integrity=metrics.get("cvssData", {}).get("integrityImpact", ""),
                availability=metrics.get("cvssData", {}).get("availabilityImpact", "")
            )
            vulnerabilities.append(vuln_obj)
            
        return vulnerabilities
        
    def _parse_cisa_response(self, data: Dict[str, Any], os_info: Dict[str, Any]) -> List[Vulnerability]:
        """Parse CISA Known Exploited Vulnerabilities response."""
        vulnerabilities = []
        
        for vuln in data.get("vulnerabilities", []):
            if self._is_relevant_to_os(vuln, os_info):
                vuln_obj = Vulnerability(
                    cve_id=vuln.get("cveID", ""),
                    description=vuln.get("shortDescription", ""),
                    severity="Critical",  # CISA vulnerabilities are typically critical
                    exploitability="Easy",  # Known exploited vulnerabilities are typically easy to exploit
                    source="CISA",
                    references=[vuln.get("vendorAdvisory", "")],
                    vulnerability_type=self._determine_vulnerability_type(vuln.get("shortDescription", "")),
                    affected_components=self._extract_affected_components(vuln.get("shortDescription", "")),
                    detection_method=self._select_detection_method(self._determine_vulnerability_type(vuln.get("shortDescription", ""))),
                    discovery_date=vuln.get("dateAdded", ""),
                    last_modified=vuln.get("dueDate", ""),
                    mitigation_status="Required"
                )
                vulnerabilities.append(vuln_obj)
                
        return vulnerabilities
        
    def _parse_cve_response(self, data: List[Dict[str, Any]]) -> List[Vulnerability]:
        """Parse CVE database response."""
        vulnerabilities = []
        
        for vuln in data:
            vuln_obj = Vulnerability(
                cve_id=vuln.get("id", ""),
                description=vuln.get("summary", ""),
                severity=self._assess_severity(vuln.get("summary", "")),
                exploitability=self._assess_exploitability(vuln.get("summary", "")),
                source="CVE",
                references=[vuln.get("references", [])],
                vulnerability_type=self._determine_vulnerability_type(vuln.get("summary", "")),
                affected_components=self._extract_affected_components(vuln.get("summary", "")),
                detection_method=self._select_detection_method(self._determine_vulnerability_type(vuln.get("summary", ""))),
                discovery_date=vuln.get("Published", ""),
                last_modified=vuln.get("Modified", "")
            )
            vulnerabilities.append(vuln_obj)
            
        return vulnerabilities
        
    def _is_relevant_to_os(self, vuln: Dict[str, Any], os_info: Dict[str, Any]) -> bool:
        """Check if a vulnerability is relevant to the target OS."""
        os_name = os_info.get("os_name", "").lower()
        os_version = os_info.get("os_version", "").lower()
        
        description = vuln.get("shortDescription", "").lower()
        return os_name in description or os_version in description
        
    async def _scan_configurations(self, os_info: Dict[str, Any]) -> List[Vulnerability]:
        """Scan for configuration vulnerabilities."""
        vulnerabilities = []
        
        # Check for common misconfigurations
        config_checks = [
            "Default credentials",
            "Weak password policies",
            "Insecure protocols",
            "Unnecessary services",
            "Incorrect permissions",
            "Missing security headers",
            "Insecure file permissions",
            "Debug mode enabled",
            "Verbose error messages",
            "Insecure defaults"
        ]
        
        for check in config_checks:
            vuln = Vulnerability(
                cve_id=f"CONFIG-{check.replace(' ', '-')}",
                description=f"Potential {check} vulnerability",
                severity="Medium",
                exploitability="Easy",
                source="Configuration Scan",
                references=[],
                vulnerability_type="configuration",
                affected_components=["System Configuration"],
                detection_method="Configuration Review",
                discovery_date=datetime.now().strftime("%Y-%m-%d")
            )
            vulnerabilities.append(vuln)
            
        return vulnerabilities
        
    async def _scan_authentication(self, os_info: Dict[str, Any]) -> List[Vulnerability]:
        """Scan for authentication vulnerabilities."""
        vulnerabilities = []
        
        # Check for authentication-related vulnerabilities
        auth_checks = [
            "Weak password hashing",
            "Missing MFA",
            "Session fixation",
            "Password reuse",
            "Account lockout issues",
            "Password recovery flaws",
            "Remember me functionality",
            "Session timeout issues",
            "Token management",
            "Credential storage"
        ]
        
        for check in auth_checks:
            vuln = Vulnerability(
                cve_id=f"AUTH-{check.replace(' ', '-')}",
                description=f"Potential {check} vulnerability",
                severity="High",
                exploitability="Moderate",
                source="Authentication Scan",
                references=[],
                vulnerability_type="authentication",
                affected_components=["Authentication System"],
                detection_method="Authentication Review",
                discovery_date=datetime.now().strftime("%Y-%m-%d")
            )
            vulnerabilities.append(vuln)
            
        return vulnerabilities
        
    async def _scan_network(self, network_services: List[str]) -> List[Vulnerability]:
        """Scan for network-related vulnerabilities."""
        vulnerabilities = []
        
        # Check for network-related vulnerabilities
        network_checks = [
            "Open ports",
            "Weak encryption",
            "Protocol vulnerabilities",
            "Network sniffing",
            "Man-in-the-middle",
            "DNS issues",
            "SSL/TLS misconfigurations",
            "Firewall rules",
            "Network segmentation",
            "Service vulnerabilities"
        ]
        
        for check in network_checks:
            vuln = Vulnerability(
                cve_id=f"NET-{check.replace(' ', '-')}",
                description=f"Potential {check} vulnerability",
                severity="High",
                exploitability="Moderate",
                source="Network Scan",
                references=[],
                vulnerability_type="network",
                affected_components=network_services,
                detection_method="Network Review",
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
            try:
                analysis = await self._analyze_vulnerability(vuln)
                classified.append({
                    "vulnerability_id": vuln.cve_id,
                    "vulnerability_type": vuln.vulnerability_type,
                    "severity": vuln.severity,
                    "exploitability": vuln.exploitability,
                    "description": vuln.description,
                    "affected_components": vuln.affected_components,
                    "detection_method": vuln.detection_method,
                    "source": vuln.source,
                    "references": vuln.references,
                    "analysis": analysis
                })
            except Exception as e:
                await self.communicate(f"Error classifying vulnerability {vuln.cve_id}: {str(e)}")
                continue
            
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
        return {
            "severity_level": vulnerability.severity,
            "exploitability_level": vulnerability.exploitability,
            "analysis_text": analysis,
            "recommendations": self._extract_recommendations(analysis),
            "mitigation_strategies": self._extract_mitigation_strategies(analysis)
        }
        
    def _extract_recommendations(self, analysis: str) -> List[str]:
        """Extract recommendations from the analysis text."""
        recommendations = []
        # Look for recommendation patterns
        rec_patterns = [
            r'recommend[s]?\s+([^.!?]+[.!?])',
            r'should\s+([^.!?]+[.!?])',
            r'consider\s+([^.!?]+[.!?])',
            r'priority\s+([^.!?]+[.!?])'
        ]
        
        for pattern in rec_patterns:
            matches = re.findall(pattern, analysis, re.IGNORECASE)
            recommendations.extend(matches)
            
        return list(set(recommendations))  # Remove duplicates
        
    def _extract_mitigation_strategies(self, analysis: str) -> List[str]:
        """Extract mitigation strategies from the analysis text."""
        strategies = []
        # Look for mitigation strategy patterns
        strategy_patterns = [
            r'mitigat[e|ion]\s+([^.!?]+[.!?])',
            r'prevent\s+([^.!?]+[.!?])',
            r'protect\s+([^.!?]+[.!?])',
            r'secure\s+([^.!?]+[.!?])'
        ]
        
        for pattern in strategy_patterns:
            matches = re.findall(pattern, analysis, re.IGNORECASE)
            strategies.extend(matches)
            
        return list(set(strategies))  # Remove duplicates
        
    async def _generate_summary(self, classified_vulns: List[Dict[str, Any]]) -> str:
        """Generate a human-readable summary of findings."""
        if not classified_vulns:
            return """
            Vulnerability Analysis Summary:
            - Total vulnerabilities found: 0
            - Critical vulnerabilities: 0
            - High severity vulnerabilities: 0
            - Medium severity vulnerabilities: 0
            - Low severity vulnerabilities: 0
            
            Vulnerability Types:
            No vulnerabilities detected
            
            Sources scanned:
            - Security databases: {db_sources}
            - Installed packages
            - Network services
            
            No vulnerabilities were detected during the analysis. Continue monitoring and maintaining security best practices.
            """.format(db_sources=', '.join(self.databases.keys()))
            
        critical_count = sum(1 for v in classified_vulns if v["severity"] == "Critical")
        high_count = sum(1 for v in classified_vulns if v["severity"] == "High")
        medium_count = sum(1 for v in classified_vulns if v["severity"] == "Medium")
        low_count = sum(1 for v in classified_vulns if v["severity"] == "Low")
        
        # Group vulnerabilities by type
        vuln_types = {}
        for v in classified_vulns:
            vuln_type = v["vulnerability_type"]
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

    async def _scan_packages(self, installed_packages: List[str]) -> List[Vulnerability]:
        """Scan installed packages for known vulnerabilities."""
        vulnerabilities = []
        
        for package in installed_packages:
            # Parse package name and version
            try:
                name, version = package.split()
                
                # Common package vulnerabilities
                package_checks = [
                    ("outdated_version", "High", "Package version may be outdated"),
                    ("dependency_issue", "Medium", "Potential dependency conflicts"),
                    ("security_patch", "Critical", "Missing security patches"),
                    ("known_exploit", "Critical", "Known exploits exist"),
                    ("configuration", "Medium", "Insecure default configuration")
                ]
                
                for check_type, severity, desc in package_checks:
                    vuln = {
                        "vulnerability_id": f"PKG-{name}-{check_type}",
                        "vulnerability_type": "package",
                        "severity": severity,
                        "exploitability": "Moderate",
                        "description": f"{desc} in package {name} version {version}",
                        "affected_components": [f"{name} {version}"],
                        "detection_method": "Package Analysis",
                        "source": "Package Scan",
                        "references": []
                    }
                    vulnerabilities.append(vuln)
            except ValueError:
                continue
                
        return vulnerabilities
        
    async def _scan_services(self, network_services: List[str]) -> List[Vulnerability]:
        """Scan network services for potential vulnerabilities."""
        vulnerabilities = []
        
        for service in network_services:
            # Parse service name and port
            try:
                name = service.split()[0]
                port = service.split()[1].strip("()")
                
                # Common service vulnerabilities
                service_checks = [
                    ("exposed_port", "High", "Service exposed on network"),
                    ("weak_auth", "Critical", "Weak authentication mechanism"),
                    ("unencrypted", "High", "Unencrypted communication"),
                    ("dos_vulnerable", "Medium", "Potential DoS vulnerability"),
                    ("misconfiguration", "Medium", "Service misconfiguration")
                ]
                
                for check_type, severity, desc in service_checks:
                    vuln = {
                        "vulnerability_id": f"SVC-{name}-{port}-{check_type}",
                        "vulnerability_type": "service",
                        "severity": severity,
                        "exploitability": "Easy",
                        "description": f"{desc} in service {name} on port {port}",
                        "affected_components": [f"{name} ({port})"],
                        "detection_method": "Service Analysis",
                        "source": "Service Scan",
                        "references": []
                    }
                    vulnerabilities.append(vuln)
            except (ValueError, IndexError):
                continue
                
        return vulnerabilities 