"""Command-line changes that keep the command's effect but change its text.

These follow the evasion classes in Uetz et al., "You Cannot Escape Me: Detecting Evasions of SIEM Rules"
(USENIX Security 2024). Only process-creation events are changed, in the CommandLine field.
`case` is a control: Sigma matching ignores case by default, so it must not evade.
"""
import random
import re

MUTATIONS = ("quotes", "dash", "spaces", "case")


def _split(cmd):
    """Split into the program part and the argument part. The program can be quoted."""
    m = re.match(r'\s*("[^"]*"|\S+)(.*)$', cmd, re.S)
    return (m.group(1), m.group(2)) if m else (cmd, "")


def _quotes(args):
    # Windows argument parsing removes an empty pair of quotes inside a word: po""wershell runs as powershell.
    def one(m):
        w = m.group(0)
        return w[:2] + '""' + w[2:]
    # Words of letters only, not inside an existing quoted string.
    parts = re.split(r'("[^"]*")', args)
    return "".join(p if p.startswith('"') else re.sub(r"(?<![\w\\/:.])[A-Za-z]{4,}(?![\w\\/:.])", one, p) for p in parts)


def _dash(args):
    # PowerShell accepts -x and /x for its own parameters. Other programs differ (cmd.exe needs /c), so
    # mutate() applies this change to powershell.exe only.
    def one(m):
        return m.group(1) + ("/" if m.group(2) == "-" else "-") + m.group(3)
    return re.sub(r"(^|\s)([-/])(?=[A-Za-z])()", one, args)


def _spaces(args):
    parts = re.split(r'("[^"]*")', args)
    return "".join(p if p.startswith('"') else re.sub(r" +", "   ", p) for p in parts)


def _case(args, seed):
    rnd = random.Random(seed)
    return "".join(c.upper() if rnd.random() < 0.5 else c.lower() for c in args)


def mutate(event, kind):
    """Return a changed copy of a process-creation event, or None if the change does nothing."""
    cmd = event.get("CommandLine")
    if not isinstance(cmd, str) or not cmd.strip():
        return None
    prog, args = _split(cmd)
    if kind == "dash" and "powershell" not in str(event.get("Image", "")).lower():
        return None
    new = {"quotes": _quotes, "dash": _dash, "spaces": _spaces}[kind](args) if kind != "case" else _case(args, cmd)
    if new == args:
        return None
    return {**event, "CommandLine": prog + new}
