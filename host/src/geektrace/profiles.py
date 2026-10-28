from copy import deepcopy

# The device profile is what actually reaches the phone: it decides how many
# payload bytes are copied out of the target and whether user stacks are
# sampled. Keeping it here means the profile is a real switch instead of a
# label, and the report can state exactly what was collected.
PROFILES = {
    "ai": {
        "description": "Default. Full crypto/TLS payload within limits; directly consumable by AI.",
        "capture": {"crypto": "keys", "tls": "plaintext-64k", "file": "metadata+sample"},
        "stack": "off",
        "coverage": False,
        "include_ambient": False,
        "max_payload": 64 * 1024,
        "device_supported": True,
        "device": {
            "payload_limit": 255,
            "stack": False,
            "eager_uprobes": False,
        },
    },
    "stealth": {
        "description": "Fewest probes, metadata and fingerprints only, no plaintext or keys.",
        "capture": {"crypto": "metadata", "tls": "metadata", "file": "metadata"},
        "stack": "off",
        "coverage": False,
        "include_ambient": False,
        "max_payload": 512,
        "device_supported": True,
        "device": {
            "payload_limit": 64,
            "stack": False,
            "eager_uprobes": False,
        },
    },
    "coverage": {
        "description": "Native block coverage with bitmap counters; payload collection minimized.",
        "capture": {"crypto": "metadata", "tls": "metadata", "file": "metadata"},
        "stack": "off",
        "coverage": True,
        "include_ambient": False,
        "max_payload": 512,
        "device_supported": False,
        "device": {
            "payload_limit": 0,
            "stack": False,
            "eager_uprobes": False,
        },
    },
    "deep": {
        "description": "Optional QBDI instruction/branch tracing. Injects code; non-stealth.",
        "capture": {"crypto": "keys", "tls": "plaintext", "file": "sample"},
        "stack": "unwind",
        "coverage": True,
        "include_ambient": True,
        "max_payload": 1024 * 1024,
        "non_stealth": True,
        "device_supported": False,
        "device": {
            "payload_limit": 255,
            "stack": True,
            "eager_uprobes": False,
        },
    },
    "safe": {
        "description": "Metadata only with aggressive redaction; no sensitive values.",
        "capture": {"crypto": "metadata", "tls": "metadata", "file": "metadata"},
        "stack": "off",
        "coverage": False,
        "include_ambient": False,
        "max_payload": 0,
        "redact": True,
        "device_supported": True,
        "device": {
            "payload_limit": 0,
            "stack": False,
            "eager_uprobes": False,
        },
    },
}


def get_profile(name: str) -> dict:
    try:
        return deepcopy(PROFILES[name])
    except KeyError as exc:
        raise ValueError(
            f"unknown profile {name!r}; choose from {', '.join(PROFILES)}"
        ) from exc


def profile_names() -> list[str]:
    return list(PROFILES)


def device_options(name: str) -> dict:
    """Device-side switches for a profile (payload budget and stack)."""
    profile = get_profile(name)
    device = dict(profile.get("device") or {})
    device.setdefault("payload_limit", 255)
    device.setdefault("stack", False)
    device.setdefault("eager_uprobes", False)
    return device


def device_supported(name: str) -> bool:
    return bool(get_profile(name).get("device_supported"))
