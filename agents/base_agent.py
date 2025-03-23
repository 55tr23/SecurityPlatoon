from typing import Dict, Any, List
from pydantic import BaseModel
from langchain_openai import ChatOpenAI
from langchain.prompts import ChatPromptTemplate
from langchain.schema import BaseMessage
import os
from dotenv import load_dotenv

load_dotenv()

class AgentState(BaseModel):
    """State for each agent in the system."""
    messages: List[BaseMessage] = []
    current_task: str = ""
    findings: Dict[str, Any] = {}
    status: str = "idle"

class BaseAgent:
    def __init__(self, name: str, role: str):
        self.name = name
        self.role = role
        self.llm = ChatOpenAI(
            model="gpt-4-turbo-preview",
            temperature=0.7
        )
        self.state = AgentState()
        
    async def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process input data and return results."""
        raise NotImplementedError
        
    def update_state(self, new_state: Dict[str, Any]):
        """Update the agent's state with new information."""
        self.state = AgentState(**{**self.state.dict(), **new_state})
        
    def get_state(self) -> Dict[str, Any]:
        """Get the current state of the agent."""
        return self.state.dict()
        
    async def communicate(self, message: str) -> str:
        """Communicate with other agents or human operators."""
        prompt = ChatPromptTemplate.from_messages([
            ("system", f"You are {self.name}, a {self.role}. Communicate clearly and professionally."),
            ("human", "{message}")
        ])
        
        chain = prompt | self.llm
        response = await chain.ainvoke({"message": message})
        return response.content 