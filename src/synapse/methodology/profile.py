from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from pathlib import Path
import yaml
import logging

logger = logging.getLogger(__name__)

class PhaseStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"

class PrerequisiteCondition(BaseModel):
    condition_type: str
    target: Optional[str] = None
    value: Optional[str] = None

class ChecklistMapping(BaseModel):
    service_type: str
    checklists: List[str]

class PhaseDefinition(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    order: int = 0
    prerequisites: List[PrerequisiteCondition] = Field(default_factory=list)
    checklists: List[str] = Field(default_factory=list)
    checklist_mappings: List[ChecklistMapping] = Field(default_factory=list)

class PhaseProgress(BaseModel):
    status: PhaseStatus = PhaseStatus.PENDING
    completed_checklists: List[str] = Field(default_factory=list)
    notes: Optional[str] = None

class MethodologyProfile(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    version: str = "1.0"
    phases: List[PhaseDefinition]

class ProfileLoader:
    def __init__(self, profiles_dir: Optional[Path] = None):
        self.profiles_dir = profiles_dir or (Path(__file__).parent / "data" / "profiles")
        self.profiles: Dict[str, MethodologyProfile] = {}
        self.load_profiles()
    
    def load_profiles(self) -> None:
        if not self.profiles_dir.exists():
            return
        for file_path in self.profiles_dir.glob("*.yaml"):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    if data:
                        profile = MethodologyProfile(**data)
                        self.profiles[profile.id] = profile
            except Exception as e:
                logger.error(f"Failed to load profile {file_path}: {e}")

    def get_profile(self, profile_id: str) -> Optional[MethodologyProfile]:
        return self.profiles.get(profile_id)
        
    def get_all_profiles(self) -> List[MethodologyProfile]:
        return list(self.profiles.values())
        
    def load_custom_profile(self, file_path: Path) -> Optional[MethodologyProfile]:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                if data:
                    profile = MethodologyProfile(**data)
                    self.profiles[profile.id] = profile
                    return profile
        except Exception as e:
            logger.error(f"Failed to load custom profile {file_path}: {e}")
        return None

ProfileRegistry = ProfileLoader  # Alias for compatibility if requested
