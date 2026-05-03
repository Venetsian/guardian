"""Joomla CMS detector (v1.5 skeleton).

For v1.5, this module exists only to declare the Joomla admin paths so
the CMSRegistry can register them with the POST-flood detector. Joomla
auth-failure detection (POST /administrator/index.php returning HTTP 200
on both success and failure) requires response-body inspection or
sequence tracking — that work lands in v1.6+ when the new web servers
need it.

Until then, Joomla sites get:
  - Universal web rules (404 storms, structural tripwires, instant
    patterns, suspicious patterns)
  - POST-flood guarding /administrator/index.php
  - The CMS-mismatched WordPress attacks (e.g. /wp-login.php on a
    Joomla site) fall through to the universal 404-storm rules

That covers the realistic threat model for now.
"""

from .cms_base import CMSDetectorBase


class JoomlaDetector(CMSDetectorBase):
    CMS_NAME = 'joomla'
    ADMIN_PATHS = [
        '/administrator/index.php',
    ]

    # process_line() inherited as a no-op. v1.6+ will fill this in.
