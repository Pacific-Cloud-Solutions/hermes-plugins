"""Tool schema — what the model sees."""

TOOL_NAME = "web_headers"

WEB_HEADERS_SCHEMA = {
    "name": TOOL_NAME,
    "description": (
        "Read-only audit of HTTP security headers declared in local web server "
        "configuration (nginx and Apache). Reports missing or weak HSTS, "
        "Content-Security-Policy, X-Content-Type-Options, X-Frame-Options and "
        "Referrer-Policy declarations, banner version disclosure, and nginx blocks "
        "that silently drop inherited headers. Each finding cites the file and line "
        "it came from, plus a coverage block naming every check that could not run. "
        "Reads configuration only: it does not fetch a page, test a URL, or open a "
        "socket. Never modifies the system. Pass nothing for a local audit; pass "
        "`root` only to audit a mounted filesystem, and only paths from the fixed "
        "check list are ever read."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "root": {
                "type": "string",
                "description": (
                    "Filesystem prefix to audit instead of the running host — e.g. a "
                    "mounted image at /mnt/suspect. Only the fixed set of web server "
                    "configuration paths is read beneath it."
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