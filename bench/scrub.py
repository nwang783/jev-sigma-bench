"""Remove the lab artifacts that reveal the label before an event goes to Jev.

The audit found that the attack and benign events come from different machines and years, so a model
can tell them apart with no security knowledge: lab user names (81% of attack events, 0% of benign),
Sysmon RuleName values such as "technique_id=T1059.001", Atomic Red Team paths, dates, and build versions.
Sigma always sees the original events. Only the Jev input is scrubbed.
"""
import re

# Fields that carry the behavior. All other fields (times, ids, GUIDs, hashes, versions, RuleName) are dropped.
KEEP = ("Image", "OriginalFileName", "Description", "Product", "Company", "CommandLine", "CurrentDirectory",
        "User", "IntegrityLevel", "ParentImage", "ParentCommandLine", "ParentUser",
        "EventType", "TargetObject", "Details", "TargetFilename", "ScriptBlockText", "Path")
SYSTEM_NAMES = {"système": "SYSTEM", "system": "SYSTEM", "service local": "LOCAL SERVICE",
                "local service": "LOCAL SERVICE", "service réseau": "NETWORK SERVICE", "network service": "NETWORK SERVICE"}
LAB = re.compile(r"(?i)sigmacatchvm|attackrange|midgardnet|supporthub|swachchhandap?|frack113|xodih|\bwick\b"
                 r"|\b(?:ar-win|desktop|laptop|win)-[a-z0-9]+\b")
SUBS = [
    (re.compile(r"(?i)\\?AtomicRedTeam\\atomics\\T\d{4}(?:\.\d{3})?(?:\\(?:src|bin))?"), r"\\Tools"),
    (re.compile(r"(?i)atomic[-_ ]?red[-_ ]?team"), "Tools"),
    (re.compile(r"\bT1\d{3}(?:\.\d{3})?[_-]?"), ""),
    (re.compile(r"(?i)atomic"), "app"),
    (re.compile(r"S-1-5-21-\d+-\d+-\d+-\d+"), "S-1-5-21-0-0-0-1001"),
    (re.compile(r"(?i)(C:\\Users\\)(?!Public\b|Default\b|All Users\b)[^\\\"'\s]+"), r"\1user"),
]


def _user(value):
    dom, _, name = value.rpartition("\\")
    if dom.upper() in ("NT AUTHORITY", "AUTORITE NT"):
        return "NT AUTHORITY\\" + SYSTEM_NAMES.get(name.lower(), name)
    # The benign machines have no Administrator account, so that name would reveal the label. IntegrityLevel stays.
    return "WORKSTATION\\user"


def scrub(event):
    out = {}
    for k in KEEP:
        v = event.get(k)
        if v in (None, "", "-"):
            continue
        if not isinstance(v, str):
            out[k] = v
            continue
        if k in ("User", "ParentUser"):
            out[k] = _user(v)
            continue
        for pat, rep in SUBS:
            v = pat.sub(rep, v)
        out[k] = LAB.sub("WORKSTATION", v)
    return out
