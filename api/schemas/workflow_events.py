from __future__ import annotations

from typing import Any, Dict, Literal, Optional

from pydantic import BaseModel, Field


class AgentError(BaseModel):
    message: str
    details: str = ""


class AgentStatusEvent(BaseModel):
    event: Literal["agent_status"] = "agent_status"
    agent: str
    status: Literal["started", "completed", "failed"]
    timestamp: str
    data: Optional[Dict[str, Any]] = None
    error: Optional[AgentError] = None


class WorkflowCompletedEvent(BaseModel):
    event: Literal["workflow_completed"] = "workflow_completed"
    status: Literal["completed", "failed"]
    timestamp: str
    message: Optional[str] = None
    summary: Optional[Dict[str, Any]] = None
    error: Optional[AgentError] = None


class WorkflowTriggerRequest(BaseModel):
    repo_url: str = Field(..., examples=["https://github.com/example/vulnerable-app"])
    branch: str = Field("main", examples=["main"])
    triggered_by: str = Field("ui", examples=["ui"])
