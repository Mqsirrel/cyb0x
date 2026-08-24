"""Shared DataTable helpers for smooth repopulation."""

from __future__ import annotations

from typing import Any, List
from textual.widgets import DataTable


def capture_cursor(table: DataTable) -> int:
    """Captures the current cursor row so it survives a clear/rebuild cycle."""
    try:
        return max(0, int(table.cursor_row or 0))
    except Exception:
        return 0


def restore_cursor(table: DataTable, previous_row: int) -> None:
    """Restores the cursor to its pre-repopulate position (clamped to table size)."""
    if previous_row <= 0 or not table.row_count:
        return
    try:
        table.move_cursor(row=min(previous_row, table.row_count - 1))
    except Exception:
        pass


def build_rows(items: List[Any], renderer) -> List[tuple]:
    """Applies ``renderer(item) -> tuple`` over items for batched row construction."""
    return [renderer(item) for item in items]
