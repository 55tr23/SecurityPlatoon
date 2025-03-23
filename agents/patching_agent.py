from typing import Dict, Any, List, Optional
from .base_agent import BaseAgent, AgentState
from pydantic import BaseModel
import subprocess
import os
import sys
import logging
from datetime import datetime
import re

class Patch(BaseModel):
    """Model for a security patch."""
    vulnerability_id: str
    description: str
    implementation_steps: List[str]
    rollback_procedure: str
    success_probability: float
    potential_impacts: List[str]
    status: str = "pending"
    applied_at: Optional[datetime] = None
    requires_rollback: bool = False
    error: Optional[str] = None

class PatchingAgent(BaseAgent):
    def __init__(self):
        super().__init__("Patching Agent", "security patch developer")
        self.patches = []
        self.logger = logging.getLogger(__name__)
        
    async def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process input data to develop and apply patches."""
        try:
            vulnerabilities = input_data.get("vulnerabilities", [])
            exploit_attempts = input_data.get("exploit_attempts", [])
            patches = []
            
            # Develop patches for all vulnerabilities
            for vuln in vulnerabilities:
                # Prioritize vulnerabilities with exploit attempts
                has_exploit_attempt = any(attempt["vulnerability_id"] == vuln["vulnerability_id"] for attempt in exploit_attempts)
                if has_exploit_attempt or vuln.get("severity", "").lower() in ["critical", "high"]:
                    patch = await self._develop_patch(vuln)
                    if patch:
                        patches.append(patch)
            
            # Then apply the patches
            for patch in patches:
                try:
                    await self._apply_patch(patch)
                except Exception as e:
                    self.logger.error(f"Error applying patch {patch.vulnerability_id}: {str(e)}")
                    patch.status = "Failed"
                    patch.rollback_required = True
            
            self.update_state({
                "current_task": "patch development and application",
                "findings": patches,
                "status": "completed"
            })
            
            return {
                "patches": patches,
                "summary": await self._generate_summary(patches)
            }
        except Exception as e:
            self.update_state({
                "current_task": "patch development and application",
                "findings": [],
                "status": "error",
                "error": str(e)
            })
            return {
                "patches": [],
                "summary": f"Error in patch development and application: {str(e)}"
            }
        
    async def _develop_patch(self, vulnerability: Dict[str, Any]) -> Patch:
        """Develop a patch for a specific vulnerability."""
        vuln_id = vulnerability.get("vulnerability_id", "unknown")
        vuln_type = vulnerability.get("vulnerability_type", "unknown")
        severity = vulnerability.get("severity", "Unknown")
        description = vulnerability.get("description", "")
        
        prompt = f"""
        Develop a patch for the following vulnerability:
        ID: {vuln_id}
        Type: {vuln_type}
        Severity: {severity}
        Description: {description}
        
        Provide a structured response with the following sections:
        
        1. Patch Description:
        [Provide a clear description of what the patch does]
        
        2. Implementation Commands:
        [List the exact commands to run, one per line, starting with "Command:"]
        
        3. Rollback Commands:
        [List the exact commands to rollback the patch, one per line, starting with "Command:"]
        
        4. Success Probability:
        [Provide a number between 0 and 1]
        
        5. Potential Impacts:
        [List potential impacts of applying the patch]
        """
        
        analysis = await self.communicate(prompt)
        
        # Parse the analysis into structured data
        implementation_steps = self._extract_implementation_steps(analysis)
        rollback_procedure = self._extract_rollback_procedure(analysis)
        success_probability = self._assess_success_probability(analysis)
        potential_impacts = self._extract_potential_impacts(analysis)
        
        # Extract patch description from the analysis
        description_lines = []
        for line in analysis.split('\n'):
            if line.strip().lower().startswith('patch description:'):
                continue
            if line.strip().lower().startswith('implementation commands:'):
                break
            if line.strip():
                description_lines.append(line.strip())
        patch_description = ' '.join(description_lines)
        
        return Patch(
            vulnerability_id=vuln_id,
            description=patch_description,
            implementation_steps=implementation_steps,
            rollback_procedure=rollback_procedure,
            success_probability=success_probability,
            potential_impacts=potential_impacts
        )
        
    async def _apply_patch(self, patch: Patch) -> bool:
        """Apply the patch to the system."""
        try:
            self.logger.info(f"Applying patch for vulnerability: {patch.vulnerability_id}")
            
            # Create backup directory
            backup_dir = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            os.makedirs(backup_dir, exist_ok=True)
            
            # Execute each implementation step
            for i, step in enumerate(patch.implementation_steps, 1):
                self.logger.info(f"Executing step {i}/{len(patch.implementation_steps)}: {step}")
                
                # Skip empty or invalid commands
                if not step or len(step) < 2:
                    self.logger.warning(f"Skipping invalid command at step {i}")
                    continue
                    
                # Handle different command types
                if step.lower().startswith('pip'):
                    # Handle pip commands
                    if 'install' in step.lower():
                        # Extract package name and version if specified
                        parts = step.split()
                        if len(parts) >= 3:
                            package = parts[2]
                            try:
                                subprocess.run([sys.executable, '-m', 'pip', 'install', package], 
                                            check=True, capture_output=True, text=True)
                                self.logger.info(f"Successfully installed package: {package}")
                            except subprocess.CalledProcessError as e:
                                self.logger.error(f"Failed to install package {package}: {e.stderr}")
                                raise
                    elif 'upgrade' in step.lower():
                        # Extract package name if specified
                        parts = step.split()
                        if len(parts) >= 3:
                            package = parts[2]
                            try:
                                subprocess.run([sys.executable, '-m', 'pip', 'install', '--upgrade', package],
                                            check=True, capture_output=True, text=True)
                                self.logger.info(f"Successfully upgraded package: {package}")
                            except subprocess.CalledProcessError as e:
                                self.logger.error(f"Failed to upgrade package {package}: {e.stderr}")
                                raise
                elif step.lower().startswith(('apt', 'yum')):
                    # Skip package manager commands on Windows
                    self.logger.warning(f"Skipping package manager command on Windows: {step}")
                    continue
                elif step.lower().startswith('sudo'):
                    # Skip sudo commands on Windows
                    self.logger.warning(f"Skipping sudo command on Windows: {step}")
                    continue
                else:
                    # Handle other commands
                    try:
                        # Split command into parts and execute
                        cmd_parts = step.split()
                        if cmd_parts:
                            result = subprocess.run(cmd_parts, 
                                                 check=True, 
                                                 capture_output=True, 
                                                 text=True)
                            self.logger.info(f"Successfully executed command: {step}")
                    except subprocess.CalledProcessError as e:
                        self.logger.error(f"Command failed: {e.stderr}")
                        raise
                    except Exception as e:
                        self.logger.error(f"Error executing command '{step}': {str(e)}")
                        raise
            
            # Update patch status
            patch.status = "applied"
            patch.applied_at = datetime.now()
            patch.requires_rollback = True
            
            self.logger.info(f"Successfully applied patch for vulnerability: {patch.vulnerability_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to apply patch: {str(e)}")
            patch.status = "failed"
            patch.error = str(e)
            return False
            
    async def _rollback_patch(self, patch: Patch) -> bool:
        """Rollback a failed patch using the rollback procedure."""
        try:
            self.logger.info(f"Rolling back patch for vulnerability {patch.vulnerability_id}")
            
            # Execute rollback procedure
            if patch.rollback_procedure:
                result = subprocess.run(patch.rollback_procedure, shell=True, capture_output=True, text=True)
                if result.returncode != 0:
                    raise Exception(f"Rollback failed: {result.stderr}")
            
            patch.status = "Rolled Back"
            self.logger.info(f"Successfully rolled back patch for vulnerability {patch.vulnerability_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to rollback patch: {str(e)}")
            return False
        
    def _extract_implementation_steps(self, analysis: str) -> List[str]:
        """Extract implementation steps from the analysis string."""
        steps = []
        current_section = None
        
        # Split into lines and process each line
        lines = analysis.split('\n')
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # Check for section headers
            if line.lower().startswith('implementation commands:'):
                current_section = 'implementation'
                continue
            elif line.lower().startswith('rollback commands:'):
                current_section = 'rollback'
                continue
                
            # Only process lines in the implementation section
            if current_section != 'implementation':
                continue
                
            # Skip lines that are clearly headers or descriptions
            if any(line.lower().startswith(header) for header in [
                'step', 'description', 'note', 'warning', 'important',
                'implementation', 'procedure', 'process', 'method',
                'overview', 'summary', 'details', 'information',
                'this patch', 'the patch', 'update', 'changes',
                'performance', 'compatibility', 'potential', 'impact'
            ]):
                continue
                
            # Skip lines that are just numbers or bullet points without commands
            if re.match(r'^[\d\.\-\*]+$', line):
                continue
                
            # Skip lines that are just descriptive text without commands
            if not any(cmd in line.lower() for cmd in [
                'command:', 'run:', 'execute:', 'type:', 'enter:',
                'sudo', 'pip', 'apt', 'yum', 'npm', 'gem', 'chmod',
                'chown', 'mv', 'cp', 'rm', 'mkdir', 'touch', 'echo',
                'git', 'docker', 'kubectl', 'helm', 'terraform',
                'install', 'upgrade', 'update', 'configure', 'set',
                'enable', 'disable', 'start', 'stop', 'restart'
            ]):
                continue
                
            # Clean up the command
            if ':' in line:
                line = line.split(':', 1)[1].strip()
                
            # Skip empty or invalid commands
            if not line or len(line) < 2:
                continue
                
            # Skip commands that are just descriptions
            if any(desc in line.lower() for desc in [
                'this patch', 'the patch', 'update', 'changes',
                'performance', 'compatibility', 'potential', 'impact',
                'may require', 'could lead', 'should be', 'must be',
                'recommended', 'suggested', 'important', 'note',
                'locate', 'find', 'identify', 'configure', 'implement',
                'modify', 'add', 'remove', 'change', 'set', 'enable',
                'disable', 'increase', 'decrease', 'update', 'upgrade',
                'install', 'uninstall', 'apply', 'restore', 'backup',
                'copy', 'move', 'delete', 'create', 'generate'
            ]):
                continue
                
            # Format pip commands properly
            if line.lower().startswith('pip'):
                parts = line.split()
                if len(parts) >= 2:
                    if parts[1] == 'install':
                        if len(parts) >= 3:
                            package = parts[2]
                            line = f"pip install {package}"
                    elif parts[1] == 'upgrade':
                        if len(parts) >= 3:
                            package = parts[2]
                            line = f"pip install --upgrade {package}"
                        else:
                            line = "pip install --upgrade pip"
                
            # Add the command to steps
            steps.append(line)
            
        return steps
        
    def _extract_rollback_procedure(self, analysis: str) -> str:
        """Extract rollback procedure from the analysis."""
        for line in analysis.split('\n'):
            if "rollback" in line.lower():
                return line.strip()
        return "Standard system restore procedure"
        
    def _assess_success_probability(self, analysis: str) -> float:
        """Assess the probability of patch success."""
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
        
    async def _generate_summary(self, patches: List[Patch]) -> str:
        """Generate a summary of patch development and application results."""
        if not patches:
            return "No patches were developed or applied during this analysis."
            
        applied_patches = sum(1 for patch in patches if patch.status == "Applied")
        failed_patches = sum(1 for patch in patches if patch.status == "Failed")
        rolled_back_patches = sum(1 for patch in patches if patch.status == "Rolled Back")
        high_probability_patches = sum(1 for patch in patches if patch.success_probability >= 0.8)
        avg_probability = sum(patch.success_probability for patch in patches) / len(patches)
        
        summary = f"""
        Patch Development and Application Summary:
        - Total patches developed: {len(patches)}
        - Successfully applied: {applied_patches}
        - Failed to apply: {failed_patches}
        - Rolled back: {rolled_back_patches}
        - High probability patches: {high_probability_patches}
        - Average success probability: {avg_probability:.2f}
        
        Detailed patch documentation and implementation results have been prepared.
        """
        
        return summary 