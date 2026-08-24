"""Data-driven methodology profiles (phases, prerequisites, completion gates).

A profile is pure data: it routes checklist categories to phases, declares
ordering dependencies, and names alternative unlock conditions (prerequisites)
and evidence gates for completion. All evaluation logic lives in
``synapse.assessment.engine.evaluate_phase_progress`` — profiles never contain
behavior, so new methodologies require no core code changes.
"""

from typing import List, Optional, Dict
from pydantic import BaseModel
from pathlib import Path
import yaml
import logging

logger = logging.getLogger(__name__)


class PrerequisiteCondition(BaseModel):
    """Alternative unlock condition for a phase (OR-ed against depends_on).

    condition_type:
      - "target_status": target.status has reached ``value``
        (discovered < scanning < enumerated < foothold < pwned)
      - "evidence_type": evidence with proof_type == ``value`` exists
    """

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
    # Checklist categories routed into this phase (first phase by order wins
    # if two phases claim the same category).
    checklist_categories: List[str] = []
    # Phases that must COMPLETED before this one unlocks (linear spine).
    depends_on: List[str] = []
    # Alternative unlock conditions enabling non-linear branch jumps.
    prerequisites: List[PrerequisiteCondition] = []
    # Proof types required before this phase counts as completed even when all
    # its checks are resolved (e.g. foothold gated on user_flag capture).
    evidence_required: List[str] = []
    checklist_mappings: List[ChecklistMapping] = []


class MethodologyProfile(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    version: str = "1.0"
    phases: List[PhaseDefinition]

    def ordered_phases(self) -> List[PhaseDefinition]:
        return sorted(self.phases, key=lambda p: p.order)


class ProfileLoader:
    """Loads methodology profiles from YAML files in a directory."""

    def __init__(self, profiles_dir: Optional[Path] = None):
        self.profiles_dir = profiles_dir or (Path(__file__).parent / "data" / "profiles")
        self.profiles: Dict[str, MethodologyProfile] = {}
        self.load_profiles()

    def load_profiles(self) -> None:
        if not self.profiles_dir.exists():
            return
        for file_path in sorted(self.profiles_dir.glob("*.yaml")):
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


ProfileRegistry = ProfileLoader  # Alias for compatibility
