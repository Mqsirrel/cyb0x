"""Data models and schemas for Synapse."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class TargetStatus(str, Enum):
    DISCOVERED = "discovered"
    SCANNING = "scanning"
    ENUMERATED = "enumerated"
    FOOTHOLD = "foothold"
    PWNED = "pwned"
    IGNORED = "ignored"


class ServiceStatus(str, Enum):
    UNTESTED = "untested"
    IN_PROGRESS = "in_progress"
    ENUMERATED = "enumerated"
    VULNERABLE = "vulnerable"
    DEAD_END = "dead_end"


class ChecklistStatus(str, Enum):
    TODO = "todo"
    RUNNING = "running"
    CHECKED = "checked"
    FINDING = "finding"
    DEAD_END = "dead_end"


class LeadPriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class LeadStatus(str, Enum):
    BACKLOG = "backlog"
    IN_PROGRESS = "in_progress"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"


class CredentialType(str, Enum):
    PASSWORD = "password"
    NTLM_HASH = "ntlm_hash"
    KERBEROS_TICKET = "kerberos_ticket"
    SSH_KEY = "ssh_key"
    API_TOKEN = "api_token"
    PIN = "pin"
    CERTIFICATE = "certificate"
    OTHER = "other"


class ProofType(str, Enum):
    USER_FLAG = "user_flag"
    ROOT_FLAG = "root_flag"
    PROOF_SCREENSHOT = "screenshot"
    COMMAND_OUTPUT = "command_output"
    CONFIG_LEAK = "config_leak"
    CREDENTIAL_DUMP = "credential_dump"


class ChecklistItem(BaseModel):
    id: Optional[int] = None
    service_id: int
    category: str = "enum"
    title: str
    description: str = ""
    command_template: str = ""
    status: ChecklistStatus = ChecklistStatus.TODO
    severity: SeverityLevel = SeverityLevel.INFO
    remediation: str = ""
    cve_refs: List[str] = Field(default_factory=list)
    output_snippet: str = ""
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class Service(BaseModel):
    id: Optional[int] = None
    target_id: int
    port: int
    protocol: str = "tcp"
    name: str = "unknown"
    product: str = ""
    version: str = ""
    banner: str = ""
    status: ServiceStatus = ServiceStatus.UNTESTED
    notes: str = ""
    checklists: List[ChecklistItem] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class Target(BaseModel):
    id: Optional[int] = None
    ip: str
    hostname: str = ""
    os: str = "Unknown"
    status: TargetStatus = TargetStatus.DISCOVERED
    in_scope: bool = True
    tags: List[str] = Field(default_factory=list)
    notes: str = ""
    services: List[Service] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class Lead(BaseModel):
    id: Optional[int] = None
    target_id: Optional[int] = None
    target_ip: Optional[str] = None
    title: str
    description: str = ""
    priority: LeadPriority = LeadPriority.MEDIUM
    severity: SeverityLevel = SeverityLevel.INFO
    status: LeadStatus = LeadStatus.BACKLOG
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class Credential(BaseModel):
    id: Optional[int] = None
    target_id: Optional[int] = None
    target_ip: Optional[str] = None
    username: str
    secret: str
    cred_type: CredentialType = CredentialType.PASSWORD
    domain: str = ""
    service_scope: str = ""
    tested_targets: Dict[str, Any] = Field(default_factory=dict)
    notes: str = ""
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class Evidence(BaseModel):
    id: Optional[int] = None
    target_id: int
    target_ip: Optional[str] = None
    service_id: Optional[int] = None
    checklist_id: Optional[int] = None
    proof_type: ProofType = ProofType.COMMAND_OUTPUT
    title: str
    command: str = ""
    output: str = ""
    flag_hash: str = ""
    screenshot_path: str = ""
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class PivotRoute(BaseModel):
    id: Optional[int] = None
    name: str
    jump_host_ip: str
    target_subnet: str
    tunnel_type: str = "ligolo_ng"
    local_bind: str = "127.0.0.1:1080"
    notes: str = ""
    status: str = "active"
    created_at: datetime = Field(default_factory=_utcnow)


class CommandRecord(BaseModel):
    id: Optional[int] = None
    target_id: Optional[int] = None
    target_ip: Optional[str] = None
    service_id: Optional[int] = None
    checklist_id: Optional[int] = None
    command: str
    return_code: int = 0
    stdout: str = ""
    stderr: str = ""
    duration_seconds: float = 0.0
    extracted_flags: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_utcnow)

