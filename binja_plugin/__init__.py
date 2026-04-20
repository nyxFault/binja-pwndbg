"""Binary Ninja plugin entrypoint for binja-pwndbg live RPC sync."""

# Import side-effects register PluginCommand handlers.
from . import binja_rpc_server  # noqa: F401

# Module Loaded
print("[nyxFault pwndbg-rpc] Plugin loaded.")

