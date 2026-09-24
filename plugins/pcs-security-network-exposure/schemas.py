"""Tool schema — what the model sees."""

TOOL_NAME = "network_exposure"

NETWORK_EXPOSURE_SCHEMA = {
    "name": TOOL_NAME,
    "description": (
        "Read-only audit of local network exposure. Reports which services on this "
        "host are reachable beyond loopback, prioritised by what the service is — a "
        "database or container socket on every interface is a far more serious "
        "finding than a web server that is meant to be reachable. Reads the "
        "kernel's socket tables from /proc and falls back to service configuration "
        "files when those are unavailable. Returns findings that each cite their "
        "source, plus a coverage block naming every check that could not run and "
        "which tier produced the result. Never modifies the system and never opens "
        "a socket, connects anywhere, or runs ss/netstat/lsof: this reads files, it "
        "does not scan. Pass nothing for a local audit; pass `root` only to audit a "
        "mounted filesystem, and only paths from the fixed check list are read."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "root": {
                "type": "string",
                "description": (
                    "Filesystem prefix to audit instead of the running host — e.g. a "
                    "mounted image at /mnt/suspect. Only the fixed set of socket-table "
                    "and configuration paths is read beneath it."
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