"""
Bug Hunter AI — Patch Applicator
Applies approved patches to files after creating backups.
NEVER auto-applies — requires explicit approval.
"""
from __future__ import annotations

import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from app.database.models import RemediationAction

logger = logging.getLogger(__name__)


class PatchApplicator:
    """
    Safely applies approved file patches.

    Workflow:
    1. Validate the file exists
    2. Create a timestamped backup
    3. Apply the unified diff
    4. Return backup path
    """

    def apply(self, action: RemediationAction) -> str:
        """
        Apply a patch to the target file.

        Args:
            action: The approved RemediationAction containing the diff

        Returns:
            Path to the created backup file

        Raises:
            ValueError: If the action is missing required data
            RuntimeError: If the patch fails to apply
        """
        if not action.target_file:
            raise ValueError("RemediationAction has no target_file")
        if not action.patch_diff:
            raise ValueError("RemediationAction has no patch_diff")

        target = Path(action.target_file).expanduser().resolve()
        if not target.exists():
            raise RuntimeError(f"Target file not found: {target}")

        # Create backup
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup_path = target.parent / f"{target.name}.bak.{ts}"
        shutil.copy2(target, backup_path)
        logger.info(f"Backup created: {backup_path}")

        # Apply diff using 'patch' command if available, else try Python patching
        import subprocess
        import tempfile

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".diff", delete=False
        ) as tf:
            tf.write(action.patch_diff)
            diff_path = tf.name

        try:
            result = subprocess.run(
                ["patch", "-u", str(target), diff_path],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                # Restore from backup
                shutil.copy2(backup_path, target)
                raise RuntimeError(
                    f"Patch failed (exit {result.returncode}): {result.stderr}"
                )
            logger.info(f"Patch applied successfully to {target}")
            return str(backup_path)
        finally:
            import os
            if os.path.exists(diff_path):
                os.unlink(diff_path)
