"""
WP-Guardian Firewall Backend Factory
Creates the appropriate backend based on configuration.
"""

import logging

logger = logging.getLogger('wp-guardian.backends')

# All supported backend types and their import paths
BACKEND_REGISTRY = {
    'csf':       ('backends.csf',       'CSFBackend',       'CSF (ConfigServer Firewall)'),
    'mikrotik':  ('backends.mikrotik',   'MikroTikBackend',  'MikroTik RouterOS via SSH'),
    'firewalld': ('backends.firewalld',  'FirewalldBackend', 'firewalld (RHEL/AlmaLinux/CyberPanel)'),
    'nftables':  ('backends.nftables',   'NftablesBackend',  'nftables (direct)'),
    'pfsense':   ('backends.pfsense',    'PfSenseBackend',   'pfSense / OPNsense via API'),
    'opnsense':  ('backends.pfsense',    'PfSenseBackend',   'OPNsense via API (alias for pfsense)'),
}


def create_backend(config):
    """
    Create and return the configured firewall backend.

    Reads [firewall] backend = ... from config, then initializes the
    appropriate backend class with the config object.

    Args:
        config: ConfigParser instance with WP-Guardian config loaded.

    Returns:
        An instance of a FirewallBackend subclass.

    Raises:
        ValueError: If the backend type is unknown or misconfigured.
    """
    backend_type = config.get('firewall', 'backend', fallback='csf').strip().lower()

    # Handle 'opnsense' as alias for 'pfsense' backend
    if backend_type == 'opnsense':
        # Set platform hint so the backend knows it's OPNsense
        if not config.has_section('pfsense'):
            config.add_section('pfsense')
        if not config.get('pfsense', 'platform', fallback=''):
            config.set('pfsense', 'platform', 'opnsense')

    if backend_type in BACKEND_REGISTRY:
        module_path, class_name, description = BACKEND_REGISTRY[backend_type]

        logger.info(f"Initializing firewall backend: {description}")

        # Dynamic import
        import importlib
        module = importlib.import_module(module_path)
        backend_class = getattr(module, class_name)
        return backend_class(config)

    else:
        supported = ', '.join(sorted(BACKEND_REGISTRY.keys()))
        raise ValueError(
            f"Unknown firewall backend: '{backend_type}'. "
            f"Supported backends: {supported}. "
            f"Check [firewall] backend = ... in wp-guardian.conf"
        )


def list_backends():
    """Return a list of (name, description) tuples for all supported backends."""
    seen = set()
    result = []
    for name, (module_path, class_name, description) in sorted(BACKEND_REGISTRY.items()):
        if class_name not in seen:
            result.append((name, description))
            seen.add(class_name)
    return result
