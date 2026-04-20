#!/usr/bin/env python3
"""pwndbg commands that call Binary Ninja in an isolated subprocess."""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import xmlrpc.client
from typing import Optional

import gdb

_OPENED_BINARY_PATH: Optional[str] = None
_OPENED_ANALYSIS_PATH: Optional[str] = None
_HELPER_TIMEOUT_SECONDS = 90
_BINJA_WRAPPER_PATH = os.path.expanduser("~/.local/bin/binaryninja")
_CACHED_PYTHON: Optional[str] = None
_CACHED_WRAPPER_ENV: Optional[dict] = None
_RPC_URL: Optional[str] = os.environ.get("BINJA_PWNDBG_RPC_URL", "http://127.0.0.1:31337")
_RPC_PROXY: Optional[xmlrpc.client.ServerProxy] = None

_LEVEL_ALIASES = {
    "asm": "disasm",
    "disasm": "disasm",
    "disassembly": "disasm",
    "llil": "llil",
    "mlil": "mlil",
    "hlil": "hlil",
    "pseudo": "pseudoc",
    "pseudo-c": "pseudoc",
    "pseudoc": "pseudoc",
    "c": "pseudoc",
    "decompile": "pseudoc",
}
_LEVEL_CHOICES = ["disasm", "llil", "mlil", "hlil", "pseudoc"]

# ANSI colors (works in pwndbg terminal output)
_RESET = "\x1b[0m"
_C_HEADER = "\x1b[1;36m"
_C_ADDR = "\x1b[33m"
_C_KEYWORD = "\x1b[35m"
_C_STRING = "\x1b[32m"
_C_NUMBER = "\x1b[36m"
_C_COMMENT = "\x1b[90m"

_BN_HELPER = r"""
import json
import sys

op = sys.argv[1]
target_path = sys.argv[2]
addr = None
level = "pseudoc"

if op == "init":
    pass
elif op == "function_text":
    if len(sys.argv) < 4:
        print(json.dumps({"ok": False, "error": "missing address"}))
        raise SystemExit(0)
    addr = int(sys.argv[3], 0)
    if len(sys.argv) > 4:
        level = sys.argv[4]
elif op == "calltree":
    if len(sys.argv) < 4:
        print(json.dumps({"ok": False, "error": "missing address"}))
        raise SystemExit(0)
    addr = int(sys.argv[3], 0)
elif op == "resolve_symbol":
    if len(sys.argv) < 4:
        print(json.dumps({"ok": False, "error": "missing symbol name"}))
        raise SystemExit(0)
    symbol_name = sys.argv[3]

result = {"ok": False}

try:
    import binaryninja as bn
except Exception as exc:
    result["error"] = f"binaryninja import failed: {exc}"
    print(json.dumps(result))
    raise SystemExit(0)


def fmt_disasm(func):
    lines = []
    for block in func.basic_blocks:
        # Preferred path across many BN versions.
        dis_text = getattr(block, "disassembly_text", None)
        if dis_text:
            for line in dis_text:
                addr = getattr(line, "address", None)
                tokens = getattr(line, "tokens", None)
                if addr is None or tokens is None:
                    continue
                toks = "".join(getattr(t, "text", str(t)) for t in tokens).rstrip()
                lines.append(f"0x{addr:x}: {toks}")
            continue

        # Fallback for older/newer API differences.
        addr = block.start
        while addr < block.end:
            try:
                text = func.view.get_disassembly(addr)
                length = func.view.get_instruction_length(addr)
            except Exception:
                break
            if not text:
                break
            lines.append(f"0x{addr:x}: {text.rstrip()}")
            if not isinstance(length, int) or length <= 0:
                break
            addr += length
    return "\n".join(lines)


def fmt_llil(func):
    il = getattr(func, "llil", None)
    if il is None:
        return None
    out = []
    for bb in il:
        for ins in bb:
            out.append(str(ins))
    return "\n".join(out)


def fmt_mlil(func):
    il = getattr(func, "mlil", None)
    if il is None:
        return None
    out = []
    for bb in il:
        for ins in bb:
            out.append(str(ins))
    return "\n".join(out)


def fmt_hlil(func):
    il = getattr(func, "hlil", None)
    if il is None:
        return None
    return str(il)


def func_brief(func):
    return {"name": str(getattr(func, "name", "<unknown>")), "start": int(getattr(func, "start", 0))}


def calltree_for(bv, func):
    incoming = []
    outgoing = []

    callers = getattr(func, "callers", None)
    if callers:
        for cf in callers:
            if cf is None:
                continue
            incoming.append(func_brief(cf))

    callees = getattr(func, "callees", None)
    if callees:
        for tf in callees:
            if tf is None:
                continue
            outgoing.append(func_brief(tf))

    if not incoming:
        try:
            for ref in bv.get_code_refs(func.start):
                src_func = getattr(ref, "function", None)
                if src_func is None:
                    continue
                incoming.append(func_brief(src_func))
        except Exception:
            pass

    def dedupe(entries):
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

    return dedupe(incoming), dedupe(outgoing)


try:
    bv = bn.load(target_path)
    if bv is None:
        result["error"] = f"failed to open BinaryView: {target_path}"
        print(json.dumps(result))
        raise SystemExit(0)

    if op == "init":
        result = {"ok": True, "path": target_path}
    elif op == "function_text":
        funcs = bv.get_functions_containing(addr)
        if not funcs:
            result["error"] = f"no function contains 0x{addr:x}"
            print(json.dumps(result))
            raise SystemExit(0)

        func = funcs[0]
        text = None
        if level == "disasm":
            text = fmt_disasm(func)
        elif level == "llil":
            text = fmt_llil(func)
        elif level == "mlil":
            text = fmt_mlil(func)
        elif level in ("hlil", "pseudoc"):
            text = fmt_hlil(func)
        else:
            result["error"] = f"unsupported level: {level}"
            print(json.dumps(result))
            raise SystemExit(0)

        if not text:
            result["error"] = f"{level} unavailable for this function"
            print(json.dumps(result))
            raise SystemExit(0)

        result = {
            "ok": True,
            "level": level,
            "func_name": func.name,
            "func_start": int(func.start),
            "text": text,
        }
    elif op == "calltree":
        funcs = bv.get_functions_containing(addr)
        if not funcs:
            result["error"] = f"no function contains 0x{addr:x}"
            print(json.dumps(result))
            raise SystemExit(0)
        func = funcs[0]
        incoming, outgoing = calltree_for(bv, func)
        result = {
            "ok": True,
            "func_name": str(func.name),
            "func_start": int(func.start),
            "incoming": incoming,
            "outgoing": outgoing,
        }
    elif op == "resolve_symbol":
        query = str(symbol_name).strip()
        funcs = []
        try:
            funcs = list(bv.get_functions_by_name(query))
        except Exception:
            funcs = []

        if not funcs:
            ql = query.lower()
            for f in bv.functions:
                name = str(getattr(f, "name", ""))
                if name.lower() == ql:
                    funcs.append(f)
            if not funcs:
                for f in bv.functions:
                    name = str(getattr(f, "name", ""))
                    if ql in name.lower():
                        funcs.append(f)
                        if len(funcs) >= 8:
                            break

        if not funcs:
            result["error"] = f"symbol not found: {query}"
            print(json.dumps(result))
            raise SystemExit(0)

        funcs.sort(key=lambda f: int(getattr(f, "start", 0)))
        f = funcs[0]
        result = {
            "ok": True,
            "name": str(getattr(f, "name", query)),
            "start": int(getattr(f, "start", 0)),
            "count": len(funcs),
        }
    else:
        result["error"] = f"unsupported operation: {op}"
except Exception as exc:
    result["error"] = str(exc)

print(json.dumps(result))
"""


def _msg(text: str) -> None:
    gdb.write(f"[binja-pwndbg] {_C_COMMENT}{text}{_RESET}\n")


def _err(text: str) -> None:
    gdb.write(f"[binja-pwndbg] error: {text}\n", gdb.STDERR)


def _colorize_text(text: str) -> str:
    # Lightweight coloring for readability in terminal.
    text = re.sub(r'(".*?")', rf"{_C_STRING}\1{_RESET}", text)
    text = re.sub(r"\b(0x[0-9a-fA-F]+|\d+)\b", rf"{_C_NUMBER}\1{_RESET}", text)
    text = re.sub(
        r"\b(if|else|for|while|return|switch|case|break|continue|goto)\b",
        rf"{_C_KEYWORD}\1{_RESET}",
        text,
    )
    return text


def _level_name(level: str) -> str:
    if level == "pseudoc":
        return "Pseudo-C"
    if level == "disasm":
        return "Disassembly"
    return level.upper()


def _current_exe() -> Optional[str]:
    inferior = gdb.selected_inferior()
    if inferior is not None and inferior.progspace is not None:
        filename = inferior.progspace.filename
        if filename:
            return filename
    return None


def _parse_address(value: str) -> int:
    # gdb.parse_and_eval lets users pass symbols/expressions, but plain
    # function symbols (e.g. "main") may need address-of.
    try:
        return int(gdb.parse_and_eval(value))
    except Exception:
        return int(gdb.parse_and_eval(f"&({value})"))


def _infer_runtime_base(binary_path: str) -> Optional[int]:
    """Infer PIE load base from `info proc mappings`."""
    try:
        out = gdb.execute("info proc mappings", to_string=True)
    except Exception:
        return None

    binary_real = os.path.realpath(binary_path)
    best: Optional[int] = None

    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("Start Addr"):
            continue

        parts = shlex.split(line)
        if len(parts) < 5:
            continue

        path = parts[-1] if len(parts) >= 6 else ""
        if not path.startswith("/"):
            continue
        if os.path.realpath(path) != binary_real:
            continue

        try:
            start = int(parts[0], 16)
        except Exception:
            continue

        if best is None or start < best:
            best = start

    return best


def _normalize_addr_for_binja(target_path: str, addr: int) -> int:
    """Map runtime addresses to static Binary Ninja addresses for PIE."""
    base = _infer_runtime_base(target_path)
    if base is None or addr < base:
        return addr
    return addr - base


def _discover_wrapper_env() -> dict:
    global _CACHED_WRAPPER_ENV
    if _CACHED_WRAPPER_ENV is not None:
        return _CACHED_WRAPPER_ENV

    discovered: dict = {}
    try:
        with open(_BINJA_WRAPPER_PATH, "r", encoding="utf-8") as f:
            text = f.read()
    except Exception:
        _CACHED_WRAPPER_ENV = discovered
        return discovered

    pyhome = re.search(r'export\s+PYTHONHOME="([^"]+)"', text)
    if pyhome:
        discovered["PYTHONHOME"] = pyhome.group(1)

    ld_path = re.search(r'export\s+LD_LIBRARY_PATH="\$\{HOME\}/([^"$]+)', text)
    if ld_path:
        discovered["BN_COMPAT_SUBDIR"] = ld_path.group(1).strip()

    exe = re.search(r'exec\s+"([^"]+/binaryninja)"\s+"\$@"', text)
    if exe:
        discovered["BINJA_INSTALL_DIR"] = os.path.dirname(exe.group(1))

    _CACHED_WRAPPER_ENV = discovered
    return discovered


def _python_executable() -> str:
    global _CACHED_PYTHON

    override = os.environ.get("BINJA_PWNDBG_PYTHON")
    if override:
        return override

    if _CACHED_PYTHON is not None:
        return _CACHED_PYTHON

    wrapper_env = _discover_wrapper_env()
    pyhome = wrapper_env.get("PYTHONHOME")
    if pyhome:
        for candidate in ("python3.13", "python3.12", "python3.11", "python3.10", "python3"):
            path = os.path.join(pyhome, "bin", candidate)
            if os.path.exists(path) and os.access(path, os.X_OK):
                _CACHED_PYTHON = path
                return path

    _CACHED_PYTHON = "python3"
    return _CACHED_PYTHON


def _bn_env() -> dict:
    env = dict(os.environ)
    env["BN_DISABLE_USER_PLUGINS"] = "1"
    env["BINARYNINJA_DISABLE_USER_PLUGINS"] = "1"
    env["QT_QPA_PLATFORM"] = "offscreen"

    wrapper_env = _discover_wrapper_env()
    pyhome = wrapper_env.get("PYTHONHOME")
    install_dir = wrapper_env.get("BINJA_INSTALL_DIR", os.path.expanduser("~/binaryninja"))
    compat_subdir = wrapper_env.get("BN_COMPAT_SUBDIR")

    if pyhome:
        env["PYTHONHOME"] = pyhome

    if install_dir and os.path.isdir(install_dir):
        py_candidates = [os.path.join(install_dir, "python"), os.path.join(install_dir, "python3")]
        existing = env.get("PYTHONPATH", "")
        merged = [p for p in py_candidates if os.path.isdir(p)]
        if existing:
            merged.append(existing)
        if merged:
            env["PYTHONPATH"] = ":".join(merged)

        existing_ld = env.get("LD_LIBRARY_PATH", "")
        ld_parts = [install_dir]
        if compat_subdir:
            compat_dir = os.path.expanduser(os.path.join("~", compat_subdir))
            if os.path.isdir(compat_dir):
                ld_parts.insert(0, compat_dir)
        if existing_ld:
            ld_parts.append(existing_ld)
        env["LD_LIBRARY_PATH"] = ":".join(ld_parts)

    return env


def _run_binja(op: str, target_path: str, addr: Optional[int] = None, level: str = "pseudoc") -> dict:
    args = [_python_executable(), "-c", _BN_HELPER, op, target_path]
    if addr is not None:
        args.append(hex(addr))
    args.append(level)

    proc = subprocess.run(
        args,
        env=_bn_env(),
        capture_output=True,
        text=True,
        timeout=_HELPER_TIMEOUT_SECONDS,
        check=False,
    )

    stdout = (proc.stdout or "").strip()
    stderr = (proc.stderr or "").strip()

    if proc.returncode != 0:
        raise RuntimeError(
            f"Binary Ninja helper failed (exit={proc.returncode}). "
            f"stderr: {stderr or '<empty>'}"
        )

    if not stdout:
        raise RuntimeError(
            "Binary Ninja helper returned no output. "
            f"stderr: {stderr or '<empty>'}"
        )

    try:
        payload = json.loads(stdout.splitlines()[-1])
    except Exception as exc:
        raise RuntimeError(
            f"Binary Ninja helper produced invalid JSON: {exc}. "
            f"stdout: {stdout[:300]} stderr: {stderr[:300]}"
        ) from exc

    if not payload.get("ok"):
        details = payload.get("error", "unknown helper error")
        if stderr:
            details = f"{details} (stderr: {stderr})"
        raise RuntimeError(details)

    return payload


def _run_binja_resolve_symbol(target_path: str, symbol_name: str) -> dict:
    args = [_python_executable(), "-c", _BN_HELPER, "resolve_symbol", target_path, symbol_name]
    proc = subprocess.run(
        args,
        env=_bn_env(),
        capture_output=True,
        text=True,
        timeout=_HELPER_TIMEOUT_SECONDS,
        check=False,
    )

    stdout = (proc.stdout or "").strip()
    stderr = (proc.stderr or "").strip()
    if proc.returncode != 0:
        raise RuntimeError(
            f"Binary Ninja helper failed (exit={proc.returncode}). "
            f"stderr: {stderr or '<empty>'}"
        )
    if not stdout:
        raise RuntimeError(
            "Binary Ninja helper returned no output. "
            f"stderr: {stderr or '<empty>'}"
        )
    try:
        payload = json.loads(stdout.splitlines()[-1])
    except Exception as exc:
        raise RuntimeError(
            f"Binary Ninja helper produced invalid JSON: {exc}. "
            f"stdout: {stdout[:300]} stderr: {stderr[:300]}"
        ) from exc
    if not payload.get("ok"):
        raise RuntimeError(payload.get("error", "unknown helper error"))
    return payload


def _rpc_proxy() -> Optional[xmlrpc.client.ServerProxy]:
    global _RPC_PROXY
    if not _RPC_URL:
        return None
    if _RPC_PROXY is None:
        _RPC_PROXY = xmlrpc.client.ServerProxy(_RPC_URL, allow_none=True)
    return _RPC_PROXY


def _rpc_ping() -> bool:
    proxy = _rpc_proxy()
    if proxy is None:
        return False
    try:
        res = proxy.ping()
        return bool(res and res.get("ok"))
    except Exception:
        return False


def _rpc_function_text(addr: int, level: str) -> dict:
    proxy = _rpc_proxy()
    if proxy is None:
        raise RuntimeError("RPC disabled")
    try:
        payload = proxy.function_text(int(addr), str(level))
    except Exception as exc:
        raise RuntimeError(f"XML-RPC request failed: {exc}") from exc
    if not payload or not payload.get("ok"):
        raise RuntimeError(payload.get("error", "XML-RPC call failed"))
    return payload


def _rpc_calltree(addr: int) -> dict:
    proxy = _rpc_proxy()
    if proxy is None:
        raise RuntimeError("RPC disabled")
    try:
        payload = proxy.calltree(int(addr))
    except Exception as exc:
        # Backward compatibility: older BN RPC plugin may not implement calltree.
        if "method \"calltree\" is not supported" in str(exc):
            raise RuntimeError("RPC_METHOD_UNSUPPORTED:calltree") from exc
        raise RuntimeError(f"XML-RPC request failed: {exc}") from exc
    if not payload or not payload.get("ok"):
        raise RuntimeError(payload.get("error", "XML-RPC call failed"))
    return payload


def _rpc_resolve_symbol(symbol_name: str) -> dict:
    proxy = _rpc_proxy()
    if proxy is None:
        raise RuntimeError("RPC disabled")
    try:
        payload = proxy.resolve_symbol(str(symbol_name))
    except Exception as exc:
        if "method \"resolve_symbol\" is not supported" in str(exc):
            raise RuntimeError("RPC_METHOD_UNSUPPORTED:resolve_symbol") from exc
        raise RuntimeError(f"XML-RPC request failed: {exc}") from exc
    if not payload or not payload.get("ok"):
        raise RuntimeError(payload.get("error", "XML-RPC call failed"))
    return payload


def _resolve_target_path(target_path: Optional[str] = None) -> str:
    global _OPENED_BINARY_PATH

    if target_path is None:
        target_path = _current_exe()

    if not target_path:
        raise RuntimeError(
            "No target binary detected. Run a program first or pass an explicit path to bn-init."
        )

    target_path = os.path.realpath(target_path)
    if not os.path.exists(target_path):
        raise RuntimeError(f"Binary does not exist: {target_path}")

    _OPENED_BINARY_PATH = target_path
    return target_path


def _default_bndb_candidates(binary_path: str) -> list[str]:
    base_dir = os.path.dirname(binary_path)
    base_name = os.path.basename(binary_path)
    return [
        f"{binary_path}.bndb",
        os.path.join(base_dir, f"{base_name}.bndb"),
        os.path.join(base_dir, f"{os.path.splitext(base_name)[0]}.bndb"),
    ]


def _analysis_path(binary_path: str) -> str:
    """
    Prefer BNDB when available so BN renames/types/comments from UI are reflected.
    """
    global _OPENED_ANALYSIS_PATH

    env_override = os.environ.get("BINJA_PWNDBG_BNDB")
    if env_override:
        path = os.path.realpath(env_override)
        if not os.path.exists(path):
            raise RuntimeError(f"BINJA_PWNDBG_BNDB does not exist: {path}")
        _OPENED_ANALYSIS_PATH = path
        return path

    if _OPENED_ANALYSIS_PATH and os.path.exists(_OPENED_ANALYSIS_PATH):
        return _OPENED_ANALYSIS_PATH

    for candidate in _default_bndb_candidates(binary_path):
        if os.path.exists(candidate):
            path = os.path.realpath(candidate)
            _OPENED_ANALYSIS_PATH = path
            return path

    return binary_path


def _set_analysis_path(path: Optional[str]) -> str:
    global _OPENED_ANALYSIS_PATH
    if not path:
        _OPENED_ANALYSIS_PATH = None
        binary = _resolve_target_path(_OPENED_BINARY_PATH)
        return _analysis_path(binary)

    resolved = os.path.realpath(path)
    if not os.path.exists(resolved):
        raise RuntimeError(f"Analysis file does not exist: {resolved}")
    _OPENED_ANALYSIS_PATH = resolved
    return resolved


def _parse_level_and_expr(arg: str, default_level: str) -> tuple[str, str]:
    tokens = arg.strip().split(maxsplit=1)
    if not tokens:
        return default_level, "$pc"

    maybe_level = _LEVEL_ALIASES.get(tokens[0].lower())
    if maybe_level:
        expr = tokens[1] if len(tokens) > 1 else "$pc"
        return maybe_level, expr

    return default_level, arg.strip()


def _resolve_expr_to_addresses(target: str, expr: str) -> tuple[int, int]:
    """
    Resolve input expression into (runtime_query_addr, bn_addr).
    If GDB symbols are missing (e.g., stripped binary), fall back to BN symbol lookup.
    """
    try:
        runtime_addr = _parse_address(expr)
        return runtime_addr, _normalize_addr_for_binja(target, runtime_addr)
    except Exception:
        pass

    query = expr.strip()
    if not query:
        raise RuntimeError("empty symbol/expression")

    if _rpc_ping():
        try:
            payload = _rpc_resolve_symbol(query)
            bn_addr = int(payload.get("start", 0))
            return bn_addr, bn_addr
        except Exception as exc:
            if "RPC_METHOD_UNSUPPORTED:resolve_symbol" not in str(exc):
                raise
            _msg("RPC server missing resolve_symbol method, falling back to local backend")

    analysis = _analysis_path(target)
    payload = _run_binja_resolve_symbol(analysis, query)
    bn_addr = int(payload.get("start", 0))
    return bn_addr, bn_addr


def _print_function_view(level: str, expr: str) -> None:
    target = _resolve_target_path(_OPENED_BINARY_PATH)
    runtime_addr, bn_addr = _resolve_expr_to_addresses(target, expr)
    payload = None
    if _rpc_ping():
        payload = _rpc_function_text(bn_addr, level)
    else:
        analysis = _analysis_path(target)
        payload = _run_binja("function_text", analysis, bn_addr, level=level)

    func_name = payload.get("func_name", "<unknown>")
    func_start = int(payload.get("func_start", 0))
    title = (
        f"{_C_HEADER}{_level_name(level)}{_RESET} "
        f"{_C_COMMENT}{func_name}{_RESET} "
        f"@ {_C_ADDR}0x{func_start:x}{_RESET} "
        f"{_C_COMMENT}(query=0x{runtime_addr:x}){_RESET}"
    )
    gdb.write(title + "\n")
    gdb.write(_colorize_text(payload.get("text", "")) + "\n")


def _print_calltree(expr: str) -> None:
    target = _resolve_target_path(_OPENED_BINARY_PATH)
    runtime_addr, bn_addr = _resolve_expr_to_addresses(target, expr)
    rpc_ok = _rpc_ping()

    def _fetch(addr: int) -> dict:
        if rpc_ok:
            try:
                return _rpc_calltree(addr)
            except Exception as exc:
                if "RPC_METHOD_UNSUPPORTED:calltree" not in str(exc):
                    raise
                _msg("RPC server missing calltree method, falling back to local backend")
        analysis_local = _analysis_path(target)
        return _run_binja("calltree", analysis_local, addr)

    payload = _fetch(bn_addr)

    # Quality-of-life fallback:
    # On stripped binaries, default `$pc` often lands in _start and can show no
    # useful edges; auto-switch to main when available.
    if (
        expr.strip() in ("", "$pc", "$rip")
        and str(payload.get("func_name", "")) == "_start"
        and not payload.get("incoming")
        and not payload.get("outgoing")
    ):
        try:
            if rpc_ok:
                try:
                    resolved = _rpc_resolve_symbol("main")
                except Exception as exc:
                    if "RPC_METHOD_UNSUPPORTED:resolve_symbol" not in str(exc):
                        raise
                    analysis_local = _analysis_path(target)
                    resolved = _run_binja_resolve_symbol(analysis_local, "main")
            else:
                analysis_local = _analysis_path(target)
                resolved = _run_binja_resolve_symbol(analysis_local, "main")

            main_addr = int(resolved.get("start", 0))
            if main_addr > 0:
                _msg("calltree at $pc is _start with no edges; showing main instead")
                payload = _fetch(main_addr)
                runtime_addr = main_addr
        except Exception:
            pass

    func_name = payload.get("func_name", "<unknown>")
    func_start = int(payload.get("func_start", 0))
    gdb.write(
        f"{_C_HEADER}Calltree{_RESET} {_C_COMMENT}{func_name}{_RESET} "
        f"@ {_C_ADDR}0x{func_start:x}{_RESET} {_C_COMMENT}(query=0x{runtime_addr:x}){_RESET}\n"
    )

    incoming = payload.get("incoming", [])
    outgoing = payload.get("outgoing", [])

    gdb.write(f"{_C_KEYWORD}Incoming callers{_RESET}\n")
    if not incoming:
        gdb.write(f"  {_C_COMMENT}<none>{_RESET}\n")
    else:
        for item in incoming:
            gdb.write(f"  <- {item.get('name', '<unknown>')} @ 0x{int(item.get('start', 0)):x}\n")

    gdb.write(f"{_C_KEYWORD}Outgoing callees{_RESET}\n")
    if not outgoing:
        gdb.write(f"  {_C_COMMENT}<none>{_RESET}\n")
    else:
        for item in outgoing:
            gdb.write(f"  -> {item.get('name', '<unknown>')} @ 0x{int(item.get('start', 0)):x}\n")


class BinjaInitCommand(gdb.Command):
    """bn-init [path]
Initialize Binary Ninja BinaryView for current inferior binary or provided path.
"""

    def __init__(self):
        super().__init__("bn-init", gdb.COMMAND_USER, gdb.COMPLETE_FILENAME)

    def invoke(self, arg: str, from_tty: bool) -> None:
        path = arg.strip() or None
        try:
            binary = _resolve_target_path(path)
            if _rpc_ping():
                _msg(f"Using live Binary Ninja XML-RPC sync at {_RPC_URL}")
                _msg("Open the same file in Binary Ninja and start Pwndbg Sync server there.")
                return

            analysis = _analysis_path(binary)
            _msg(f"Opening BinaryView in subprocess: {analysis}")
            _run_binja("init", analysis)
            if analysis != binary:
                _msg(f"Sync source: BNDB {analysis}")
            _msg(f"BinaryView ready: {analysis}")
        except Exception as exc:
            _err(str(exc))


class BinjaConnectCommand(gdb.Command):
    """bn-connect [path]
Prefer live RPC when reachable, otherwise initialize local BN/BNDB backend.
"""

    def __init__(self):
        super().__init__("bn-connect", gdb.COMMAND_USER, gdb.COMPLETE_FILENAME)

    def invoke(self, arg: str, from_tty: bool) -> None:
        path = arg.strip() or None
        try:
            binary = _resolve_target_path(path)
            if _rpc_ping():
                _msg(f"connected: rpc ({_RPC_URL})")
                _msg(f"target: {binary}")
                return

            analysis = _analysis_path(binary)
            _run_binja("init", analysis)
            if analysis != binary:
                _msg(f"connected: local bndb ({analysis})")
            else:
                _msg(f"connected: local binary ({analysis})")
        except Exception as exc:
            _err(str(exc))


class BinjaSyncCommand(gdb.Command):
    """bn-sync [path_to_bndb]
Set/refresh analysis source used by commands. If omitted, auto-detect BNDB.
"""

    def __init__(self):
        super().__init__("bn-sync", gdb.COMMAND_USER)

    def invoke(self, arg: str, from_tty: bool) -> None:
        try:
            selected = _set_analysis_path(arg.strip() or None)
            _run_binja("init", selected)
            _msg(f"sync source set to: {selected}")
            _msg("tip: save your BN database after renames to reflect updates here")
        except Exception as exc:
            _err(str(exc))


class BinjaRpcCommand(gdb.Command):
    """bn-rpc [off|URL]
Show/update XML-RPC endpoint for live sync with Binary Ninja plugin.
"""

    def __init__(self):
        super().__init__("bn-rpc", gdb.COMMAND_USER)

    def invoke(self, arg: str, from_tty: bool) -> None:
        global _RPC_URL
        global _RPC_PROXY

        value = arg.strip()
        if not value:
            status = "enabled" if _RPC_URL else "disabled"
            _msg(f"rpc {status}: {_RPC_URL or '<none>'}")
            _msg(f"rpc reachable: {'yes' if _rpc_ping() else 'no'}")
            return

        if value.lower() in ("off", "disable", "disabled"):
            _RPC_URL = None
            _RPC_PROXY = None
            _msg("rpc disabled; using subprocess/BNDB backend")
            return

        if "://" not in value:
            value = f"http://{value}"
        _RPC_URL = value
        _RPC_PROXY = None
        _msg(f"rpc endpoint set: {_RPC_URL}")
        _msg(f"rpc reachable: {'yes' if _rpc_ping() else 'no'}")


class BinjaDecompileCommand(gdb.Command):
    """bn-decompile [addr_or_symbol]
Pseudo-C style decompilation for containing function. Defaults to current PC.
"""

    def __init__(self):
        super().__init__("bn-decompile", gdb.COMMAND_USER, gdb.COMPLETE_SYMBOL)

    def invoke(self, arg: str, from_tty: bool) -> None:
        try:
            _print_function_view("pseudoc", arg.strip() or "$pc")
        except Exception as exc:
            _err(str(exc))


class BinjaIlCommand(gdb.Command):
    """bn-il <level> [addr_or_symbol]
level: disasm | llil | mlil | hlil | pseudoc
Defaults address/symbol to current PC.
"""

    def __init__(self):
        super().__init__("bn-il", gdb.COMMAND_USER, gdb.COMPLETE_NONE)

    def complete(self, text: str, word: str):
        args = text.strip().split()
        # `text` is args-only (without command name).
        if len(args) <= 1 and not text.strip().endswith(" "):
            prefix = args[0].lower() if args else ""
            return [lvl for lvl in _LEVEL_CHOICES if lvl.startswith(prefix)]

        if len(args) == 1 and text.strip().endswith(" "):
            # level is already complete, now suggest symbols.
            return gdb.COMPLETE_SYMBOL

        # completing expression/symbol after level
        return gdb.COMPLETE_SYMBOL

    def invoke(self, arg: str, from_tty: bool) -> None:
        level, expr = _parse_level_and_expr(arg, default_level="pseudoc")
        try:
            _print_function_view(level, expr)
        except Exception as exc:
            _err(str(exc))


class BinjaDisasmCommand(gdb.Command):
    def __init__(self):
        super().__init__("bn-disasm", gdb.COMMAND_USER, gdb.COMPLETE_SYMBOL)

    def invoke(self, arg: str, from_tty: bool) -> None:
        try:
            _print_function_view("disasm", arg.strip() or "$pc")
        except Exception as exc:
            _err(str(exc))


class BinjaLlilCommand(gdb.Command):
    def __init__(self):
        super().__init__("bn-llil", gdb.COMMAND_USER, gdb.COMPLETE_SYMBOL)

    def invoke(self, arg: str, from_tty: bool) -> None:
        try:
            _print_function_view("llil", arg.strip() or "$pc")
        except Exception as exc:
            _err(str(exc))


class BinjaMlilCommand(gdb.Command):
    def __init__(self):
        super().__init__("bn-mlil", gdb.COMMAND_USER, gdb.COMPLETE_SYMBOL)

    def invoke(self, arg: str, from_tty: bool) -> None:
        try:
            _print_function_view("mlil", arg.strip() or "$pc")
        except Exception as exc:
            _err(str(exc))


class BinjaHlilCommand(gdb.Command):
    def __init__(self):
        super().__init__("bn-hlil", gdb.COMMAND_USER, gdb.COMPLETE_SYMBOL)

    def invoke(self, arg: str, from_tty: bool) -> None:
        try:
            _print_function_view("hlil", arg.strip() or "$pc")
        except Exception as exc:
            _err(str(exc))


class BinjaPseudoCCommand(gdb.Command):
    def __init__(self):
        super().__init__("bn-pseudoc", gdb.COMMAND_USER, gdb.COMPLETE_SYMBOL)

    def invoke(self, arg: str, from_tty: bool) -> None:
        try:
            _print_function_view("pseudoc", arg.strip() or "$pc")
        except Exception as exc:
            _err(str(exc))


class BinjaCalltreeCommand(gdb.Command):
    """bn-calltree [addr_or_symbol]
Show direct incoming callers and outgoing callees for the containing function.
"""

    def __init__(self):
        super().__init__("bn-calltree", gdb.COMMAND_USER, gdb.COMPLETE_SYMBOL)

    def invoke(self, arg: str, from_tty: bool) -> None:
        try:
            _print_calltree(arg.strip() or "$pc")
        except Exception as exc:
            _err(str(exc))


def register() -> None:
    BinjaConnectCommand()
    BinjaInitCommand()
    BinjaSyncCommand()
    BinjaRpcCommand()
    BinjaDecompileCommand()
    BinjaIlCommand()
    BinjaDisasmCommand()
    BinjaLlilCommand()
    BinjaMlilCommand()
    BinjaHlilCommand()
    BinjaPseudoCCommand()
    BinjaCalltreeCommand()
    _msg("commands loaded: bn-connect, bn-init, bn-sync, bn-rpc, bn-decompile, bn-il, bn-disasm, bn-llil, bn-mlil, bn-hlil, bn-pseudoc, bn-calltree")


register()
