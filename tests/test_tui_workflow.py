"""Tests for the TUI Guided Workflow & Profile Modal interfaces."""

import pytest
from synapse.tui.app import SynapseTUI
from synapse.tui.modals.profile_modal import ProfileModal
from synapse.tui.modals.guided_phase_modal import GuidedPhaseModal

@pytest.mark.asyncio
async def test_tui_profile_workflow():
    app = SynapseTUI(db_path=":memory:")
    async with app.run_test() as pilot:
        # Check that we can open the profile modal
        await pilot.press("p")
        await pilot.pause(0.1)
        
        assert isinstance(app.screen, ProfileModal)
        
        # Switch profile to ejptv2
        # Use down arrow to navigate option list to ejptv2
        # Let's just click 'Select Profile' or directly call action
        await pilot.press("escape")  # Close it for now, test if it closes
        await pilot.pause(0.1)
        assert not isinstance(app.screen, ProfileModal)

        # Open guide modal
        await pilot.press("g")
        await pilot.pause(0.1)
        assert isinstance(app.screen, GuidedPhaseModal)
        
        await pilot.press("escape")
        await pilot.pause(0.1)
        assert not isinstance(app.screen, GuidedPhaseModal)

        # Check stats banner text contains the current profile name
        # Default is "Network Pentest"
        banner = app.query_one("#stats-banner")
        # Ensure it contains Network Pentest
        assert "Network Pentest" in str(banner.render())
