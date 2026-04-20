#!/usr/bin/env python3
"""Binary Ninja plugin: expose current BinaryView over XML-RPC for pwndbg sync."""

from __future__ import annotations

import json
import threading
from socketserver import ThreadingMixIn
from xmlrpc.server import SimpleXMLRPCServer

from binaryninja import PluginCommand, log_info, log_error

_SERVER = None
_SERVER_THREAD = None
_ACTIVE_BV = None
_ACTIVE_BV_PATH = None
_DEFAULT_HOST = "127.0.0.1"
_DEFAULT_PORT = 31337


class _ThreadedXMLRPCServer(ThreadingMixIn, SimpleXMLRPCServer):
    daemon_threads = True
    allow_reuse_address = True


def _find_func(addr: int):
    funcs = _ACTIVE_BV.get_functions_containing(addr)
    if funcs:
        return funcs[0]
    return None


def _fmt_disasm(func):
    lines = []
    for block in func.basic_blocks:
        dis_text = getattr(block, "disassembly_text", None)
        if dis_text:
            for line in dis_text:
                line_addr = getattr(line, "address", None)
                tokens = getattr(line, "tokens", None)
                if line_addr is None or tokens is None:
                    continue
                toks = "".join(getattr(t, "text", str(t)) for t in tokens).rstrip()
                lines.append(f"0x{line_addr:x}: {toks}")
            continue

        addr = block.start
        while addr < block.end:
            try:
                text = _ACTIVE_BV.get_disassembly(addr)
                length = _ACTIVE_BV.get_instruction_length(addr)
            except Exception:
                break
            if not text:
                break
            lines.append(f"0x{addr:x}: {text.rstrip()}")
            if not isinstance(length, int) or length <= 0:
                break
            addr += length
    return "\n".join(lines)


def _fmt_llil(func):
    il = getattr(func, "llil", None)
    if il is None:
        return None
    out = []
    for bb in il:
        for ins in bb:
            out.append(str(ins))
    return "\n".join(out)


def _fmt_mlil(func):
    il = getattr(func, "mlil", None)
    if il is None:
        return None
    out = []
    for bb in il:
        for ins in bb:
            out.append(str(ins))
    return "\n".join(out)


def _fmt_hlil(func):
    il = getattr(func, "hlil", None)
    if il is None:
        return None
    return str(il)


def _func_brief(func):
    return {"name": str(getattr(func, "name", "<unknown>")), "start": int(getattr(func, "start", 0))}


def _calltree_for(func):
    incoming = []
    outgoing = []

    # Preferred function-level APIs if available.
    callers = getattr(func, "callers", None)
    if callers:
        for cf in callers:
            if cf is None:
                continue
            incoming.append(_func_brief(cf))

    callees = getattr(func, "callees", None)
    if callees:
        for tf in callees:
            if tf is None:
                continue
            outgoing.append(_func_brief(tf))

    # Fallback incoming reconstruction via code refs.
    if not incoming:
        try:
            for ref in _ACTIVE_BV.get_code_refs(func.start):
                src_func = getattr(ref, "function", None)
                if src_func is None:
                    continue
                incoming.append(_func_brief(src_func))
        except Exception:
            pass

    # Deduplicate/sort.
    def _dedupe(entries):
        seen = set()
        out = []
        for e in entries:
            key = (e["name"], e["start"])
            if key in seen:
                continue
            seen.add(key)
            out.append(e)
        out.sort(key=lambda x: (x["start"], x["name"]))
        return out

    return _dedupe(incoming), _dedupe(outgoing)


class _RpcMethods:
    def ping(self):
        return {"ok": True, "msg": "pong"}

    def status(self):
        if _ACTIVE_BV is None:
            return {"ok": False, "error": "no active BinaryView"}
        return {
            "ok": True,
            "path": _ACTIVE_BV.file.filename,
            "start": int(_ACTIVE_BV.start),
        }

    def function_text(self, addr: int, level: str = "pseudoc"):
        if _ACTIVE_BV is None:
            return {"ok": False, "error": "no active BinaryView"}

        func = _find_func(int(addr))
        if func is None:
            return {"ok": False, "error": f"no function contains 0x{int(addr):x}"}

        text = None
        if level == "disasm":
            text = _fmt_disasm(func)
        elif level == "llil":
            text = _fmt_llil(func)
        elif level == "mlil":
            text = _fmt_mlil(func)
        elif level in ("hlil", "pseudoc"):
            text = _fmt_hlil(func)
        else:
            return {"ok": False, "error": f"unsupported level: {level}"}

        if not text:
            return {"ok": False, "error": f"{level} unavailable for this function"}

        return {
            "ok": True,
            "level": level,
            "func_name": func.name,
            "func_start": int(func.start),
            "text": text,
            "source_path": _ACTIVE_BV.file.filename,
        }

    def calltree(self, addr: int):
        if _ACTIVE_BV is None:
            return {"ok": False, "error": "no active BinaryView"}

        func = _find_func(int(addr))
        if func is None:
            return {"ok": False, "error": f"no function contains 0x{int(addr):x}"}

        incoming, outgoing = _calltree_for(func)
        return {
            "ok": True,
            "func_name": str(func.name),
            "func_start": int(func.start),
            "incoming": incoming,
            "outgoing": outgoing,
            "source_path": _ACTIVE_BV.file.filename,
        }

    def resolve_symbol(self, name: str):
        if _ACTIVE_BV is None:
            return {"ok": False, "error": "no active BinaryView"}

        query = str(name or "").strip()
        if not query:
            return {"ok": False, "error": "empty symbol name"}

        funcs = []
        try:
            funcs = list(_ACTIVE_BV.get_functions_by_name(query))
        except Exception:
            funcs = []

        if not funcs:
            ql = query.lower()
            try:
                for f in _ACTIVE_BV.functions:
                    fn = str(getattr(f, "name", ""))
                    if fn.lower() == ql:
                        funcs.append(f)
                if not funcs:
                    for f in _ACTIVE_BV.functions:
                        fn = str(getattr(f, "name", ""))
                        if ql in fn.lower():
                            funcs.append(f)
                            if len(funcs) >= 8:
                                break
            except Exception:
                funcs = []

        if not funcs:
            return {"ok": False, "error": f"symbol not found: {query}"}

        funcs.sort(key=lambda f: int(getattr(f, "start", 0)))
        f = funcs[0]
        return {
            "ok": True,
            "name": str(getattr(f, "name", query)),
            "start": int(getattr(f, "start", 0)),
            "count": len(funcs),
        }


def _start_server(host: str, port: int):
    global _SERVER
    global _SERVER_THREAD

    if _SERVER is not None:
        return

    _SERVER = _ThreadedXMLRPCServer((host, port), allow_none=True, logRequests=False)
    _SERVER.register_instance(_RpcMethods())
    _SERVER_THREAD = threading.Thread(target=_SERVER.serve_forever, daemon=True)
    _SERVER_THREAD.start()

    log_info(f"[binja-rpc] XML-RPC server started on {host}:{port}")


def _stop_server():
    global _SERVER
    global _SERVER_THREAD
    if _SERVER is None:
        return
    try:
        _SERVER.shutdown()
        _SERVER.server_close()
    except Exception as exc:
        log_error(f"[binja-rpc] stop error: {exc}")
    _SERVER = None
    _SERVER_THREAD = None
    log_info("[binja-rpc] XML-RPC server stopped")


def start_server_for_view(bv):
    global _ACTIVE_BV
    global _ACTIVE_BV_PATH

    _ACTIVE_BV = bv
    _ACTIVE_BV_PATH = bv.file.filename if bv and bv.file else None
    _start_server(_DEFAULT_HOST, _DEFAULT_PORT)
    log_info(f"[binja-rpc] active view set: {_ACTIVE_BV_PATH}")


def stop_server_for_view(_bv):
    _stop_server()


def status_for_view(_bv):
    if _SERVER is None:
        log_info("[binja-rpc] server is not running")
        return
    log_info(f"[binja-rpc] running on {_DEFAULT_HOST}:{_DEFAULT_PORT}, active={_ACTIVE_BV_PATH}")


PluginCommand.register(
    "Pwndbg Sync\\Start XML-RPC Server",
    "Start XML-RPC server for current BinaryView (live names/types sync).",
    start_server_for_view,
)
PluginCommand.register(
    "Pwndbg Sync\\Stop XML-RPC Server",
    "Stop XML-RPC server.",
    stop_server_for_view,
)
PluginCommand.register(
    "Pwndbg Sync\\Show XML-RPC Status",
    "Show XML-RPC server status.",
    status_for_view,
)

