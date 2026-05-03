"""Drupal CMS detector (v1.5 skeleton).

Same v1.5 status as joomla.py — this module declares the Drupal admin
paths so the CMSRegistry/POST-flood watchlist knows about them. Real
auth-failure detection (POST /user/login returning 200 on both success
and failure, with redirect-back-to-login as the failure tell) lands
in v1.6+.

Drupal 7 uses /user/login while Drupal 8/9/10/11 use the same path —
so a single registration covers all supported versions.
"""

from .cms_base import CMSDetectorBase


class DrupalDetector(CMSDetectorBase):
    CMS_NAME = 'drupal'
    ADMIN_PATHS = [
        '/user/login',
    ]

    # process_line() inherited as a no-op. v1.6+ will fill this in.
