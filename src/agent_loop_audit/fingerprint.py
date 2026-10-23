"""Exact internal identity and conservative lexical classifiers; never execute."""

import re
import shlex

from .models import Limits
from .normalize import digest
from .parser import strict_json

KNOWN = {"exec_command", "shell_command", "shell", "apply_patch", "read_file",
         "write_stdin", "wait", "poll", "update_plan", "request_user_input",
         "list_tools", "search_tools"}
EXCLUDED = {"write_stdin", "wait", "poll", "update_plan", "request_user_input", "list_tools", "search_tools"}


def tool_kind(tool: tuple[str | None, str] | None) -> str | None:
    if tool and tool[0] in (None, "functions") and tool[1] in KNOWN:
        return tool[1]
    return None


def fingerprint(tool, arguments: str, context: str | None, *, custom=False) -> str:
    try:
        value = ["json", strict_json(arguments, Limits())] if not custom else ["custom", arguments]
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        value = ["literal", arguments]
    return digest([tool, value, context])


def read_like(tool, arguments: str) -> bool:
    if tool_kind(tool) not in {"exec_command", "shell_command", "shell"}:
        return False
    try:
        args = strict_json(arguments, Limits())
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        return False
    if not isinstance(args, dict):
        return False
    cmd, shell = args.get("cmd", args.get("command")), args.get("shell")
    if not isinstance(cmd, str) or not isinstance(shell, str):
        return False
    if any(char in cmd for char in "\r\n$`|;&<>*?[]{}"):
        return False
    if shell in {"pwsh", "powershell", "pwsh.exe", "powershell.exe"}:
        return re.fullmatch(r"Get-Content -LiteralPath '(?:[^']|'')+'(?: -Raw)?", cmd) is not None
    if shell not in {"sh", "bash", "zsh", "/bin/sh", "/bin/bash", "/bin/zsh"}:
        return False
    try:
        words = shlex.split(cmd, posix=True)
    except ValueError:
        return False
    if words[:2] == ["cat", "--"]:
        words = [words[0], *words[2:]]
    return (len(words) == 2 and words[0] == "cat" and bool(words[1])
            and not words[1].startswith(("-", "~")) and "\\" not in cmd)
