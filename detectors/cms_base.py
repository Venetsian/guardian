"""Base class for per-CMS web detectors (v1.5).

The web pipeline calls each CMS detector for the matching site so the
detector can run CMS-specific rules (e.g. auth failure detection). v1.5
ships only the WordPress logic (in WebDetector) plus skeletons for
Joomla and Drupal. Future versions fill those in.

A CMS module owns:
  - CMS_NAME  (the slug used by CMSRegistry: 'joomla', 'drupal', ...)
  - ADMIN_PATHS  (paths to register with the POST-flood watchlist)
  - process_line(parsed, site)  optional CMS-specific rules

The base class is deliberately tiny — most of the logic lives in the
shared web pipeline. This is just a contract.
"""


class CMSDetectorBase:
    """Contract for per-CMS web detectors."""

    CMS_NAME = 'unknown'
    ADMIN_PATHS = []

    def __init__(self, config, blocker, db, whitelist=None):
        self.config = config
        self.blocker = blocker
        self.db = db
        self.whitelist = whitelist

    def process_line(self, parsed, site=''):
        """Run CMS-specific checks on a parsed access-log line.

        Default implementation is a no-op. Subclasses override.
        """
        return
