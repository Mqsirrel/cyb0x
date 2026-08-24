import pytest
from pathlib import Path
import yaml
from synapse.methodology.profile import (
    MethodologyProfile, PhaseDefinition, PhaseStatus, PhaseProgress,
    ChecklistMapping, PrerequisiteCondition, ProfileLoader
)
from synapse.methodology.engine import MethodologyEngine

def test_models():
    prereq = PrerequisiteCondition(condition_type="port_open", target="80")
    mapping = ChecklistMapping(service_type="http", checklists=["web_basic"])
    
    phase = PhaseDefinition(
        id="test_phase",
        name="Test Phase",
        order=1,
        prerequisites=[prereq],
        checklist_mappings=[mapping]
    )
    
    profile = MethodologyProfile(
        id="test_profile",
        name="Test Profile",
        phases=[phase]
    )
    
    assert profile.id == "test_profile"
    assert len(profile.phases) == 1
    assert profile.phases[0].id == "test_phase"
    assert profile.phases[0].prerequisites[0].condition_type == "port_open"

    progress = PhaseProgress(status=PhaseStatus.IN_PROGRESS, completed_checklists=["web_basic"])
    assert progress.status == PhaseStatus.IN_PROGRESS
    assert "web_basic" in progress.completed_checklists

def test_profile_loader(tmp_path):
    profiles_dir = tmp_path / "profiles"
    profiles_dir.mkdir()
    
    custom_profile = {
        "id": "custom_1",
        "name": "Custom Profile 1",
        "version": "1.0",
        "phases": [
            {
                "id": "phase1",
                "name": "Phase 1",
                "order": 1
            }
        ]
    }
    
    custom_file = profiles_dir / "custom.yaml"
    with open(custom_file, "w") as f:
        yaml.dump(custom_profile, f)
        
    loader = ProfileLoader(profiles_dir=profiles_dir)
    assert len(loader.get_all_profiles()) == 1
    
    profile = loader.get_profile("custom_1")
    assert profile is not None
    assert profile.name == "Custom Profile 1"
    assert len(profile.phases) == 1
    assert profile.phases[0].id == "phase1"

def test_methodology_engine_integration(tmp_path):
    engine = MethodologyEngine()
    
    # Engine should load default profiles
    profiles = engine.get_available_profiles()
    assert len(profiles) >= 4 # We created 4 standard profiles
    
    profile_ids = [p.id for p in profiles]
    assert "ejptv2" in profile_ids
    assert "network_pentest" in profile_ids
    assert "web_pentest" in profile_ids
    assert "htb_lab" in profile_ids
    
    # Test setting active profile
    success = engine.set_active_profile("web_pentest")
    assert success is True
    assert engine.active_profile is not None
    assert engine.active_profile.id == "web_pentest"
    
    # Test invalid active profile
    success = engine.set_active_profile("invalid_profile")
    assert success is False
    assert engine.active_profile.id == "web_pentest" # Should not change
    
    # Test loading custom profile
    custom_profile_path = tmp_path / "custom.yaml"
    with open(custom_profile_path, "w") as f:
        f.write("""
id: "custom_2"
name: "Custom Profile 2"
version: "1.0"
phases:
  - id: "p1"
    name: "Phase 1"
    order: 1
""")
    
    success = engine.load_custom_profile(custom_profile_path)
    assert success is True
    
    custom_profile = engine.profile_loader.get_profile("custom_2")
    assert custom_profile is not None
    assert custom_profile.name == "Custom Profile 2"
