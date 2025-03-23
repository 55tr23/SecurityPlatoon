from typing import Dict, Any, List
from .base_agent import BaseAgent, AgentState
from pydantic import BaseModel

class Patch(BaseModel):
    vulnerability_id: str
    patch_description: str
    implementation_steps: List[str]
    rollback_procedure: str
    success_probability: float
    potential_impacts: List[str]

class PatchingAgent(BaseAgent):
    def __init__(self):
        super().__init__("Patching Agent", "security patch developer")
        self.patches = []
        
    async def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process vulnerabilities and develop patches."""
        vulnerabilities = input_data.get("vulnerabilities", [])
        exploit_attempts = input_data.get("exploit_attempts", [])
        
        for vuln, attempt in zip(vulnerabilities, exploit_attempts):
            if attempt["success"]:
                patch = await self._develop_patch(vuln, attempt)
                self.patches.append(patch)
                
        self.update_state({
            "current_task": "patch development",
            "findings": {"patches": [patch.dict() for patch in self.patches]},
            "status": "completed"
        })
        
        return {
            "patches": [patch.dict() for patch in self.patches],
            "summary": await self._generate_summary()
        }
        
    async def _develop_patch(self, vulnerability: Dict[str, Any], exploit_attempt: Dict[str, Any]) -> Patch:
        """Develop a patch for a specific vulnerability."""
        vuln_id = vulnerability["vulnerability"]["cve_id"]
        
        prompt = f"""
        Develop a patch for the following vulnerability:
        CVE ID: {vuln_id}
        Description: {vulnerability['vulnerability']['description']}
        Exploit Details: {exploit_attempt['details']}
        Mitigation Suggestions: {exploit_attempt['mitigation_suggestions']}
        
        Provide:
        1. Detailed patch description
        2. Step-by-step implementation instructions
        3. Rollback procedure in case of issues
        4. Success probability assessment
        5. Potential impacts of applying the patch
        """
        
        analysis = await self.communicate(prompt)
        
        # Parse the analysis into structured data
        # In a real implementation, you would use more sophisticated parsing
        implementation_steps = self._extract_implementation_steps(analysis)
        rollback_procedure = self._extract_rollback_procedure(analysis)
        success_probability = self._assess_success_probability(analysis)
        potential_impacts = self._extract_potential_impacts(analysis)
        
        return Patch(
            vulnerability_id=vuln_id,
            patch_description=analysis,
            implementation_steps=implementation_steps,
            rollback_procedure=rollback_procedure,
            success_probability=success_probability,
            potential_impacts=potential_impacts
        )
        
    def _extract_implementation_steps(self, analysis: str) -> List[str]:
        """Extract implementation steps from the analysis."""
        steps = []
        for line in analysis.split('\n'):
            if any(keyword in line.lower() for keyword in ["step", "implement", "apply"]):
                steps.append(line.strip())
        return steps
        
    def _extract_rollback_procedure(self, analysis: str) -> str:
        """Extract rollback procedure from the analysis."""
        # In a real implementation, you would use more sophisticated parsing
        for line in analysis.split('\n'):
            if "rollback" in line.lower():
                return line.strip()
        return "Standard system restore procedure"
        
    def _assess_success_probability(self, analysis: str) -> float:
        """Assess the probability of patch success."""
        # In a real implementation, you would use more sophisticated analysis
        if "high probability" in analysis.lower():
            return 0.9
        elif "moderate probability" in analysis.lower():
            return 0.7
        else:
            return 0.5
            
    def _extract_potential_impacts(self, analysis: str) -> List[str]:
        """Extract potential impacts from the analysis."""
        impacts = []
        for line in analysis.split('\n'):
            if "impact" in line.lower():
                impacts.append(line.strip())
        return impacts
        
    async def _generate_summary(self) -> str:
        """Generate a summary of patch development results."""
        if not self.patches:
            return "No patches were developed during this analysis."
            
        high_probability_patches = sum(1 for patch in self.patches if patch.success_probability >= 0.8)
        avg_probability = sum(patch.success_probability for patch in self.patches) / len(self.patches)
        
        summary = f"""
        Patch Development Summary:
        - Total patches developed: {len(self.patches)}
        - High probability patches: {high_probability_patches}
        - Average success probability: {avg_probability:.2f}
        
        Detailed patch documentation and implementation guides have been prepared.
        """
        
        return summary 