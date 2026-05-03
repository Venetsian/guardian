"""WP-Guardian detector package.

Each detector tails one or more logs and turns log lines into block decisions.
Detectors live here (one file per detector) so the main daemon stays small.

v1.5: extracted from wp-guardian.py with no behavior change.
"""

from .base import HitTracker
from .web import WebDetector
from .mail import MailDetector
from .ssh import SSHDetector
from .roundcube import RoundcubeDetector
from .distributed_auth import DistributedAuthDetector
from .post_flood import PostFloodDetector

__all__ = [
    'HitTracker',
    'WebDetector',
    'MailDetector',
    'SSHDetector',
    'RoundcubeDetector',
    'DistributedAuthDetector',
    'PostFloodDetector',
]
