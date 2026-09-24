"""Tool schema — what the model sees."""

TOOL_NAME = "auth_posture"

AUTH_POSTURE_SCHEMA = {
    "name": TOOL_NAME,
    "description": (
        "Read-only audit of local authentication posture. Reads a fixed set of "
        "well-known files (sshd_config and its drop-ins, sudoers, authorized_keys, "
        "/etc/passwd) and returns findings that each cite the file and line they "
        "came from, plus a coverage block naming every check that could not run. "
        "Never modifies the system: remediation text is advisory for a human. "
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
                    "authentication paths is read beneath it."
                ),
            },
            "include_info": {
                "type": "boolean",
                "description": "Include INFO-severity observations (default false).",
            },
        },
        "required": [],
    },
}