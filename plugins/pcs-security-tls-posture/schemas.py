"""Tool schema — what the model sees."""

TOOL_NAME = "tls_posture"

TLS_POSTURE_SCHEMA = {
    "name": TOOL_NAME,
    "description": (
        "Read-only audit of local TLS posture. Parses a fixed set of certificate "
        "files and server TLS directives (nginx, Apache) and returns findings that "
        "each cite the file and line they came from, plus a coverage block naming "
        "every check that could not run. Covers certificate expiry, key size, "
        "signature algorithm, and deprecated protocols or weak cipher suites named "
        "in server configuration. Never modifies the system and never connects to "
        "anything: this reads files on disk, it does not perform a handshake. "
        "Pass nothing for a local audit; pass `root` only to audit a mounted "
        "filesystem, and only paths from the fixed check list are ever read."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "root": {
                "type": "string",
                "description": (
                    "Filesystem prefix to audit instead of the running host — e.g. a "
                    "mounted image at /mnt/suspect. Only the fixed set of "
                    "certificate and server-config paths is read beneath it."
                ),
            },
            "include_info": {
                "type": "boolean",
                "description": "Include INFO-severity observations (default false).",
            },
            "expiry_days": {
                "type": "integer",
                "description": (
                    "Report certificates expiring within this many days (default 30). "
                    "Certificates with 7 days or fewer remaining are reported a "
                    "severity higher."
                ),
            },
        },
        "required": [],
    },
}