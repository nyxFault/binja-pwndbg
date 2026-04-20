# binja-pwndbg

<p align="left">
  <img alt="Platform Linux" src="https://img.shields.io/badge/platform-linux-blue?logo=linux">
  <img alt="Debugger pwndbg" src="https://img.shields.io/badge/debugger-pwndbg-7a3cff">
  <img alt="Disassembler Binary Ninja" src="https://img.shields.io/badge/disassembler-Binary%20Ninja-f59e0b">
  <img alt="Sync XML-RPC" src="https://img.shields.io/badge/sync-XML--RPC-22c55e">
  <img alt="Language Python" src="https://img.shields.io/badge/language-python-3776ab?logo=python&logoColor=white">
</p>

Pwndbg commands that talk to Binary Ninja: decompilation, IL levels, call trees, optional live sync over XML-RPC.

## Layout

- `plugin/binja_pwndbg.py` — load this in GDB/pwndbg
- [`bn-pwndbg-sync/`](https://github.com/nyxFault/bn-pwndbg-sync) — Binary Ninja side ([submodule](https://git-scm.com/book/en/v2/Git-Tools-Submodules)); same plugin [standalone](https://github.com/nyxFault/bn-pwndbg-sync)

## Commands (summary)

| Area | Commands |
|------|----------|
| Setup | `bn-connect`, `bn-init`, `bn-sync`, `bn-rpc` |
| Decomp / IL | `bn-decompile`, `bn-il`, `bn-disasm`, `bn-llil`, `bn-mlil`, `bn-hlil`, `bn-pseudoc` |
| Graph | `bn-calltree` |

Stripped binaries: symbol-style names (e.g. `main`) are resolved via BN when GDB has no symbol. Tab completion works for the usual symbol-style arguments.

## Requirements

- GDB with pwndbg, Python enabled
- Binary Ninja’s Python API available to the helper process (see env vars below)

## Install

Clone with submodules so `bn-pwndbg-sync` is populated:

```bash
git clone --recurse-submodules https://github.com/nyxFault/binja-pwndbg.git
```

Already cloned without submodules:

```bash
git submodule update --init --recursive
```

In `.gdbinit`:

```gdb
source /path/to/binja-pwndbg/plugin/binja_pwndbg.py
```

One-liner append:

```bash
echo 'source /path/to/binja-pwndbg/plugin/binja_pwndbg.py' >> ~/.gdbinit
```

## Binary Ninja plugin (live sync)

Repo: [bn-pwndbg-sync](https://github.com/nyxFault/bn-pwndbg-sync). Copy that tree into BN’s user plugin directory (e.g. `~/.binaryninja/plugins/`) or symlink it, restart BN, then **Plugins → Pwndbg Sync → Start XML-RPC Server** (default `127.0.0.1:31337`).

## Example

```gdb
bn-connect
bn-rpc
bn-decompile main
bn-il hlil $pc
bn-calltree main
```

## Demo

`demo/` has a small crackme (`make -C demo`, see `demo/Makefile`). Run `gdb demo/crackme`, `start`, then try `bn-connect` and `bn-decompile main`.

## Environment

| Variable | Purpose |
|----------|---------|
| `BINJA_PWNDBG_RPC_URL` | XML-RPC URL (default `http://127.0.0.1:31337`) |
| `BINJA_PWNDBG_BNDB` | Use this `.bndb` when not using RPC |
| `BINJA_PWNDBG_PYTHON` | Python binary for the BN helper subprocess |

BN work runs out-of-process so a bad BN plugin load doesn’t take GDB down. If `~/.local/bin/binaryninja` is your wrapper, the plugin tries to reuse its `PYTHONHOME` / libs. PIE targets: addresses are adjusted using `info proc mappings`. Terminal output uses basic ANSI colors.
