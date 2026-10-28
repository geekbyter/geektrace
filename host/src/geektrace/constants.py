SCHEMA_ID = "geektrace.event.v1"
SUMMARY_SCHEMA_ID = "geektrace.summary.v1"
MANIFEST_SCHEMA_ID = "geektrace.manifest.v1"
EVENT_INDEX_SCHEMA_ID = "geektrace.event-index.v1"

LAYERS = (
    "session",
    "process",
    "loader",
    "art",
    "jni",
    "syscall",
    "file",
    "net",
    "crypto",
    "binder",
    "detect",
    "coverage",
    "stack",
    "tool",
)

BACKENDS = ("ebpf", "kpm", "qbdi", "import", "demo")

CONFIDENCES = ("exact", "inferred", "partial")

PROFILE_NAMES = ("ai", "stealth", "coverage", "deep", "safe")

LOG_PREFIX = "geekbyter===>"

TOOL_NAME = "geektrace"
