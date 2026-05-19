"""Session state persistence for campaigns.

Serializes and deserializes entire campaign state for:
  - Save/restore across tool restarts
  - Team collaboration (shared session files)
  - Checkpointing long-running campaigns
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..models import Campaign, SessionState, now_iso


class SessionManager:
    """Persistent session state manager."""

    def __init__(self, session_dir: str = "") -> None:
        self.session_dir = session_dir or str(Path.home() / ".aegis" / "sessions")
        self.current: SessionState = SessionState()
        os.makedirs(self.session_dir, exist_ok=True)

    def list_sessions(self) -> list[dict]:
        """List all saved sessions."""
        sessions = []
        pattern = os.path.join(self.session_dir, "aegis_session_*.json")
        for p in sorted(Path(self.session_dir).glob("aegis_session_*.json")):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                sessions.append({
                    "path": str(p),
                    "created": data.get("saved_at", ""),
                    "target": str(data.get("campaign", {}).get("target", "")),
                    "phase": str(data.get("campaign", {}).get("phase", "")),
                })
            except Exception:
                continue
        return sessions

    def save(self, campaign: Campaign | None = None,
             path: str = "") -> str:
        """Save current session state to disk."""
        if not path:
            stamp = time.strftime("%Y%m%d_%H%M%S")
            path = os.path.join(self.session_dir, f"aegis_session_{stamp}.json")

        data = {
            "saved_at": now_iso(),
            "version": "3.0.0",
        }
        if campaign:
            data["campaign"] = campaign.to_dict()
        if self.current:
            data["session"] = self.current.to_dict()

        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)

        return path

    def load(self, path: str) -> Campaign | None:
        """Load a saved session from disk."""
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            return None

        camp_data = data.get("campaign")
        if camp_data:
            from ..models import AuthProfile, AttackBudget, ProxyConfig, TLSFingerprint
            campaign = Campaign(
                id=camp_data.get("id", ""),
                name=camp_data.get("name", ""),
                target=camp_data.get("target", ""),
                goal=camp_data.get("goal", ""),
                started_at=camp_data.get("started_at", ""),
                finished_at=camp_data.get("finished_at", ""),
            )
            phase_str = camp_data.get("phase", "init")
            try:
                from ..models import CampaignPhase
                campaign.phase = CampaignPhase(phase_str)
            except ValueError:
                pass
            self.current.campaign = campaign
            return campaign

        return None

    def clear(self) -> None:
        """Reset current session state."""
        self.current = SessionState()

    def record_endpoint(self, url: str) -> None:
        if url not in self.current.discovered_endpoints:
            self.current.discovered_endpoints.append(url)

    def record_param(self, param: str) -> None:
        if param not in self.current.discovered_params:
            self.current.discovered_params.append(param)
