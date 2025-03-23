from typing import Dict, Any, List, Optional
from pydantic import BaseModel
from langchain_openai import ChatOpenAI
from langchain.prompts import ChatPromptTemplate
from langchain.schema import BaseMessage
import os
from dotenv import load_dotenv

load_dotenv()

class AgentState(BaseModel):
    """State of an agent."""
    current_task: str = ""
    findings: List[Dict[str, Any]] = []
    status: str = "idle"
    last_update: str = ""
    error: Optional[str] = None

    def dict(self, *args, **kwargs) -> Dict[str, Any]:
        """Convert state to a dictionary, handling None values."""
        base_dict = super().dict(*args, **kwargs)
        return {
            "current_task": base_dict.get("current_task", ""),
            "findings": base_dict.get("findings", []),
            "status": base_dict.get("status", "idle"),
            "last_update": base_dict.get("last_update", ""),
            "error": base_dict.get("error", "")
        }

    def update(self, update: Dict[str, Any]) -> None:
        """Update the state with new values."""
        if "findings" in update and not isinstance(update["findings"], list):
            update["findings"] = [update["findings"]] if update["findings"] else []
        super().update(update)

class BaseAgent:
    """Base class for all agents."""
    def __init__(self, name: str, role: str):
        self.name = name
        self.role = role
        self.state = AgentState()
        self.llm = ChatOpenAI(
            model="gpt-3.5-turbo",
            temperature=0.7,
            max_tokens=2000
        )
        
    def get_state(self) -> Dict[str, Any]:
        """Get the current state of the agent."""
        return self.state.dict()
        
    def update_state(self, update: Dict[str, Any]) -> None:
        """Update the agent's state."""
        current_state = self.state.dict()
        current_state.update(update)
        self.state = AgentState(**current_state)
        
    async def communicate(self, prompt: str) -> str:
        """Communicate with the language model."""
        try:
            messages = [
                {"role": "system", "content": f"You are a {self.role}. Respond with clear, actionable insights."},
                {"role": "user", "content": prompt}
            ]
            
            response = await self.llm.ainvoke(messages)
            if response and hasattr(response, 'content'):
                return str(response.content)
            elif isinstance(response, str):
                return response
            else:
                return str(response)
        except Exception as e:
            return f"Error in communication: {str(e)}"
        
    async def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process input data and return results."""
        raise NotImplementedError 