from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, asdict

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

ADVISORIES = {
    "pypi": {
        "flask": [("<0.12.3", "CVE-2018-1000656", "high",
                   "Flask < 0.12.3 DoS via crafted JSON.")],
        "django": [("<2.2.28", "CVE-2022-28346", "critical",
                    "Django SQL injection via QuerySet.annotate (<2.2.28).")],
        "requests": [("<2.20.0", "CVE-2018-18074", "high",
                      "requests < 2.20.0 leaks Authorization on redirect.")],
        "pyyaml": [("<5.4", "CVE-2020-14343", "critical",
                    "PyYAML < 5.4 arbitrary code execution via full_load.")],
        "jinja2": [("<2.11.3", "CVE-2020-28493", "medium",
                    "Jinja2 < 2.11.3 ReDoS in urlize filter.")],
        "urllib3": [("<1.26.5", "CVE-2021-33503", "high",
                     "urllib3 < 1.26.5 ReDoS via crafted URL authority.")],
        "cryptography": [("<3.3.2", "CVE-2020-36242", "high",
                          "cryptography < 3.3.2 buffer overflow in Fernet.")],
    },
    "npm": {
        "lodash": [("<4.17.21", "CVE-2021-23337", "high",
                    "lodash < 4.17.21 command injection via template.")],
        "minimist": [("<1.2.6", "CVE-2021-44906", "critical",
                      "minimist < 1.2.6 prototype pollution.")],
        "axios": [("<0.21.2", "CVE-2021-3749", "high",
                   "axios < 0.21.2 ReDoS via trim regex.")],
        "node-fetch": [("<2.6.7", "CVE-2022-0235", "medium",
                        "node-fetch < 2.6.7 leaks cookies/Authorization on redirect.")],
    },
    "go": {
        "golang.org/x/crypto": [
            (
                "<v0.0.0-20220314234659-1baeb1ce4c0b",
                "CVE-2022-27191",
                "high",
                "golang.org/x/crypto/ssh crash via crafted packets.",
            )
        ],
    },
}

@dataclass
class Finding:
    ecosystem: str
    package: str
    version: str
    id: str
    severity: str
    summary: str
    via: str | None = None  # chain that pulled a transitive dependency in

    def to_dict(self) -> dict:
        return asdict(self)

def _norm(v: str) -> tuple:
    nums = re.findall(r"\d+", v)
    return tuple(int(n) for n in nums) if nums else (0,)

def _cmp(a: str, b: str) -> int:
    # Separate release digits from prereleases before comparing numeric parts.
    pattern = r"^[vV]?(\d+(?:\.\d+)*)(.*)$"
    ma, mb = re.match(pattern, a.strip()), re.match(pattern, b.strip())
    ta, tb = _norm(ma.group(1) if ma else a), _norm(mb.group(1) if mb else b)
    length = max(len(ta), len(tb))
    ta += (0,) * (length - len(ta))
    tb += (0,) * (length - len(tb))
    release_cmp = (ta > tb) - (ta < tb)
    if release_cmp or not (ma and mb):
        return release_cmp

    def suffix_key(suffix: str) -> tuple:
        # SemVer build metadata does not participate in precedence.
        suffix = suffix.split("+", 1)[0]
        if not suffix:
            return (1,)
        if suffix.startswith("-"):
            # SemVer numeric identifiers precede text identifiers; comparing
            # identifiers individually also preserves Go pseudo-version dates.
            identifiers = tuple(
                (0, int(part)) if part.isdigit() else (1, part)
                for part in suffix[1:].split(".")
            )
            return (0, identifiers)
        pep = re.fullmatch(
            r"[._]?(a|b|rc|dev)(\d*)(?:\.dev(\d+))?", suffix, re.IGNORECASE)
        if pep:
            stage = {"dev": 0, "a": 1, "b": 2, "rc": 3}[pep.group(1).lower()]
            dev = (0, int(pep.group(3))) if pep.group(3) is not None else (1, 0)
            return (0, ((0, stage), (0, int(pep.group(2) or 0)), dev))
        # Preserve the existing numeric fallback for unsupported suffixes.
        return (1, _norm(suffix))

    sa, sb = suffix_key(ma.group(2)), suffix_key(mb.group(2))
    return (sa > sb) - (sa < sb)

def version_matches(version: str, spec: str) -> bool:
    m = re.match(r"\s*(<=|>=|==|<|>)\s*(.+)\s*$", spec)
    if not m:
        return False
    op, target = m.group(1), m.group(2).strip()
    c = _cmp(version, target)
    return {
        "<": c < 0, "<=": c <= 0, "==": c == 0,
        ">": c > 0, ">=": c >= 0,
    }[op]

@dataclass
class Dep:
    ecosystem: str
    name: str
    version: str | None
    raw: str
    pinned: bool
    via: str | None = None

def _parse_dependency_token(text: str) -> tuple[str | None, str | None, bool] | None:
    token = text.split(";", 1)[0].strip()
    token = token.split("#", 1)[0].strip()
    if not token:
        return None
    m = re.match(
        r"^([A-Za-z0-9_.\-]+(?:\[[^\]]+\])?)\s*(==|>=|<=|~=|>|<|!=)?\s*([^\s;,]+)?",
        token)
    if not m:
        return None
    name = m.group(1).split("[", 1)[0].lower()
    op, ver = m.group(2), m.group(3)
    pinned = op == "==" and bool(ver)
    version = ver if pinned or op else (ver if op and ver else None)
    return name, version, pinned

def parse_requirements(text: str) -> list[Dep]:
    deps: list[Dep] = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        parsed = _parse_dependency_token(line)
        if not parsed:
            continue
        name, version, pinned = parsed
        deps.append(Dep("pypi", name, version, line, pinned))
    return deps

def parse_pyproject_toml(text: str) -> list[Dep]:
    try:
        import tomllib
    except Exception:
        return []

    try:
        data = tomllib.loads(text)
    except Exception:
        return []

    deps: list[Dep] = []
    project = data.get("project") or {}
    project_deps = project.get("dependencies") or []
    if not isinstance(project_deps, list):
        return []

    for dep in project_deps:
        if not isinstance(dep, str):
            continue
        parsed = _parse_dependency_token(dep)
        if not parsed:
            continue
        name, version, pinned = parsed
        deps.append(Dep("pypi", name, version, dep, pinned))
    return deps

def parse_package_json(text: str) -> list[Dep]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    deps: list[Dep] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, spec in (data.get(section) or {}).items():
            spec = str(spec)
            pinned = bool(re.match(r"^\d+\.\d+\.\d+", spec)) and not any(
                c in spec for c in "^~*x ><||")
            ver = re.sub(r"^[\^~>=<\s]+", "", spec)
            ver = ver if re.match(r"^\d", ver) else None
            deps.append(Dep("npm", name.lower(), ver, f"{name}: {spec}", pinned))
    return deps

def parse_go_mod(text: str) -> list[Dep]:
    deps: list[Dep] = []
    in_require_block = False

    for line in text.splitlines():
        line = line.strip()

        if not line or line.startswith("//"):
            continue

        if "// indirect" in line:
            continue

        if line == "require (":
            in_require_block = True
            continue

        if line.startswith("require "):
            parts = line.split()
        
            if len(parts) >= 3:
                name = parts[1]
                version = parts[2]
        
                deps.append(
                    Dep(
                        ecosystem="go",
                        name=name,
                        version=version,
                        raw=line,
                        pinned=True,
                    )
                )
        
            continue

        if in_require_block and line == ")":
            in_require_block = False
            continue

        if not in_require_block:
            continue

        parts = line.split()

        if len(parts) < 2:
            continue

        name = parts[0]
        version = parts[1]

        deps.append(
            Dep(
                ecosystem="go",
                name=name,
                version=version,
                raw=line,
                pinned=True,
            )
        )

    return deps

def _chains(graph: dict, roots: list) -> dict:
    """Shortest chain of ancestors from a root to every reachable node (BFS)."""
    chains = {r: [] for r in roots if r in graph}
    queue = list(chains)
    for node in queue:
        for child in graph[node]:
            if child not in chains:
                chains[child] = chains[node] + [node]
                queue.append(child)
    return chains

def _npm_name(path: str) -> str:
    return path.rsplit("node_modules/", 1)[-1]

def _npm_resolve(packages: dict, parent: str, name: str) -> str | None:
    # Node's lookup: parent/node_modules/name, then each ancestor's, then the root.
    while True:
        candidate = (parent + "/" if parent else "") + "node_modules/" + name
        if candidate in packages:
            return candidate
        if not parent:
            return None
        parent = (parent.rsplit("/node_modules/", 1)[0]
                  if "/node_modules/" in parent else "")

def _npm_v1_to_packages(deps: dict, parent: str = "",
                        out: dict | None = None) -> dict:
    out = {} if out is None else out
    for name, meta in deps.items():
        if not isinstance(meta, dict):
            continue
        path = (parent + "/" if parent else "") + "node_modules/" + name
        out[path] = {"version": meta.get("version"),
                     "dependencies": meta.get("requires") or {}}
        _npm_v1_to_packages(meta.get("dependencies") or {}, path, out)
    return out

def parse_package_lock(text: str) -> list[Dep]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    packages = data.get("packages")
    if isinstance(packages, dict):
        packages = {k: v for k, v in packages.items()
                    if isinstance(v, dict) and (k == "" or "node_modules/" in k)}
    else:
        packages = _npm_v1_to_packages(data.get("dependencies") or {})
    root = packages.pop("", None)
    if root is None:
        # ponytail: v1 never lists the root's own deps, so a top-level package
        # nobody requires is treated as direct. One that is both direct and
        # required elsewhere is reported with a "via"; read package.json if
        # that matters.
        required = {n for m in packages.values()
                    for n in (m.get("dependencies") or {})}
        root = {"dependencies": {_npm_name(p): "" for p in packages
                                 if p.count("node_modules/") == 1
                                 and _npm_name(p) not in required}}

    graph = {"": []}
    for path, meta in list(packages.items()) + [("", root)]:
        names = {}
        for section in ("dependencies", "optionalDependencies",
                        "peerDependencies", "devDependencies"):
            names.update(meta.get(section) or {})
        graph[path] = [p for p in (_npm_resolve(packages, path, n) for n in names)
                       if p]
    chains = _chains(graph, [""])

    deps: list[Dep] = []
    seen = set()
    # Reachable packages first, in BFS order, so the shortest chain wins a dedupe.
    order = [p for p in chains if p] + [p for p in packages if p not in chains]
    for path in order:
        meta = packages[path]
        name, version = _npm_name(path).lower(), meta.get("version")
        if not version or (name, version) in seen:
            continue
        seen.add((name, version))
        if path in chains:
            via = [_npm_name(p) for p in chains[path] if p]
        else:  # unreachable (extraneous): fall back to where it is installed
            via = path.split("node_modules/")[1:-1]
            via = [v.rstrip("/") for v in via]
        deps.append(Dep("npm", name, version, f"{path}@{version}", True,
                        " > ".join(via) or None))
    return deps

def _pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()

def _read_poetry_lock(text: str) -> list[dict]:
    """Python < 3.11 has no tomllib; poetry.lock only needs a tiny TOML subset:
    [[package]] tables with name/version and a [package.dependencies] table."""
    pkgs: list[dict] = []
    section = None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("["):
            section = line.strip("[] ")
            if line == "[[package]]":
                pkgs.append({"dependencies": {}})
            continue
        m = re.match(r'^"?([A-Za-z0-9_.\-]+)"?\s*=\s*(.*)$', line)
        if not m or not pkgs:
            continue
        key, value = m.groups()
        if section == "package" and key in ("name", "version"):
            pkgs[-1][key] = value.strip().strip('"\'')
        elif section == "package.dependencies":
            pkgs[-1]["dependencies"][key] = value
    return pkgs

def parse_poetry_lock(text: str) -> list[Dep]:
    try:
        import tomllib
        try:
            pkgs = tomllib.loads(text).get("package") or []
        except Exception:
            return []
    except ImportError:
        pkgs = _read_poetry_lock(text)

    graph: dict[str, list[str]] = {}
    versions: dict[str, str] = {}
    for pkg in pkgs:
        if not isinstance(pkg, dict) or not pkg.get("name"):
            continue
        name = _pep503(pkg["name"])
        versions.setdefault(name, str(pkg.get("version") or ""))
        graph[name] = [_pep503(d) for d in (pkg.get("dependencies") or {})]
    for children in graph.values():
        children[:] = [c for c in children if c in graph]
    # ponytail: poetry.lock does not record which packages are direct, so a
    # package nobody depends on is a root. Read pyproject.toml if a package
    # that is both direct and transitive must not show a "via".
    depended = {c for children in graph.values() for c in children}
    chains = _chains(graph, [n for n in graph if n not in depended])

    deps: list[Dep] = []
    for name in graph:
        if not versions[name]:
            continue
        via = " > ".join(chains.get(name, [])) or None
        deps.append(Dep("pypi", name, versions[name],
                        f"{name}=={versions[name]}", True, via))
    return deps

def check_offline(deps: list[Dep]) -> list[Finding]:
    findings: list[Finding] = []
    for dep in deps:
        if not dep.version:
            continue
        eco_db = ADVISORIES.get(dep.ecosystem, {})
        for spec, cve, sev, summary in eco_db.get(dep.name, []):
            if version_matches(dep.version, spec):
                findings.append(Finding(dep.ecosystem, dep.name, dep.version,
                                        cve, sev, summary, dep.via))
    findings.sort(key=lambda f: SEV_RANK.get(f.severity, 9))
    return findings

OSV_BATCH = 1000  # OSV.dev's limit on queries per /v1/querybatch request

def _osv(url: str, body: dict | None = None, timeout: float = 10.0) -> dict:
    import urllib.request

    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())

def check_online_osv(deps: list[Dep], timeout: float = 10.0) -> list[Finding]:
    eco_map = {"pypi": "PyPI", "npm": "npm", "go": "Go"}
    deps = [d for d in deps if d.version]
    # Batch queries only return vuln IDs; details are fetched once per ID.
    hits: list[tuple[Dep, str]] = []
    for i in range(0, len(deps), OSV_BATCH):
        chunk = deps[i:i + OSV_BATCH]
        queries = [{"version": d.version,
                    "package": {"name": d.name,
                                "ecosystem": eco_map[d.ecosystem]}}
                   for d in chunk]
        try:
            data = _osv("https://api.osv.dev/v1/querybatch",
                        {"queries": queries}, timeout)
        except Exception:
            continue
        # ponytail: ignores next_page_token, which OSV only sets when a single
        # package has more vulns than fit in one page; follow it if that bites.
        for dep, result in zip(chunk, data.get("results") or []):
            for vuln in (result or {}).get("vulns") or []:
                if vuln.get("id"):
                    hits.append((dep, vuln["id"]))

    def detail(vid: str) -> dict:
        try:
            return _osv(f"https://api.osv.dev/v1/vulns/{vid}", timeout=timeout)
        except Exception:
            return {}

    # One GET per advisory; sequentially a mid-sized lockfile takes minutes.
    from concurrent.futures import ThreadPoolExecutor
    ids = list(dict.fromkeys(vid for _, vid in hits))
    with ThreadPoolExecutor(max_workers=8) as pool:
        details = dict(zip(ids, pool.map(detail, ids)))

    findings: list[Finding] = []
    for dep, vid in hits:
        vuln = details[vid]
        findings.append(Finding(dep.ecosystem, dep.name, dep.version, vid,
                                _osv_severity(vuln),
                                (vuln.get("summary") or "")[:200], dep.via))
    findings.sort(key=lambda f: SEV_RANK.get(f.severity, 9))
    return findings

def _osv_severity(vuln: dict) -> str:
    db = (vuln.get("database_specific") or {})
    sev = str(db.get("severity", "")).lower()
    if sev in SEV_RANK:
        return sev
    return "medium"

def unpinned_warnings(deps: list[Dep]) -> list[Finding]:
    out: list[Finding] = []
    for dep in deps:
        if not dep.pinned:
            out.append(Finding(dep.ecosystem, dep.name, dep.version or "*",
                               "unpinned", "low",
                               "Dependency is not pinned to an exact version "
                               "— non-reproducible builds and supply-chain risk."))
    return out

def filter_by_severity(findings: list[Finding],
                       min_severity: str = "info") -> list[Finding]:
    threshold = SEV_RANK.get(min_severity, SEV_RANK["info"])
    return [f for f in findings if SEV_RANK.get(f.severity, 3) <= threshold]

def parse_file(path: str) -> list[Dep]:
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        text = fh.read()
    base = os.path.basename(path).lower()
    if base == "package-lock.json":
        return parse_package_lock(text)
    if base == "poetry.lock":
        return parse_poetry_lock(text)
    if base == "package.json":
        return parse_package_json(text)
    if base == "pyproject.toml":
        return parse_pyproject_toml(text)
    if base == "go.mod":
        return parse_go_mod(text)
    if base.endswith(".txt") or "requirements" in base:
        return parse_requirements(text)
    return parse_requirements(text)

# Lockfiles come first so their exact versions win the dedupe in run().
LOCKFILES_REPLACE = {"package-lock.json": "package.json",
                     "poetry.lock": "pyproject.toml"}
LOCKFILES = tuple(LOCKFILES_REPLACE)

def discover(path: str) -> list[str]:
    if os.path.isfile(path):
        return [path]
    found = []
    for name in LOCKFILES + ("requirements.txt", "package.json",
                             "pyproject.toml", "go.mod"):
        candidate = os.path.join(path, name)
        if os.path.isfile(candidate):
            found.append(candidate)
    # The lockfile records what is installed; its manifest only what was asked.
    for lock, manifest in LOCKFILES_REPLACE.items():
        if os.path.join(path, lock) in found:
            found = [f for f in found if f != os.path.join(path, manifest)]
    return found

def run(path: str, online: bool = False, show_unpinned: bool = True,
        min_severity: str = "info") -> dict:
    files = discover(path)
    deps: list[Dep] = []
    locked: set[tuple[str, str]] = set()
    for f in files:
        is_lock = os.path.basename(f).lower() in LOCKFILES
        for dep in parse_file(f):
            # e.g. requirements.txt next to poetry.lock: the lock already has it.
            if not is_lock and (dep.ecosystem, dep.name) in locked:
                continue
            if is_lock:
                locked.add((dep.ecosystem, dep.name))
            deps.append(dep)
    findings = check_offline(deps)
    if online:
        findings.extend(check_online_osv(deps))
    findings = filter_by_severity(findings, min_severity)
    warnings = (filter_by_severity(unpinned_warnings(deps), min_severity)
                if show_unpinned else [])
    return {
        "files": files,
        "dependency_count": len(deps),
        "vulnerabilities": [f.to_dict() for f in findings],
        "unpinned": [w.to_dict() for w in warnings],
    }

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="dependency-check",
        description="Check dependencies for known vulns and risky pinning.")
    p.add_argument("path", help="a manifest, a lockfile, or a directory")
    p.add_argument("--online", action="store_true",
                   help="also query the OSV.dev advisory API (network)")
    p.add_argument("--no-unpinned", action="store_true",
                   help="suppress unpinned-dependency warnings")
    p.add_argument("--json", action="store_true", help="emit JSON")
    p.add_argument("--min-severity", default="info", choices=list(SEV_RANK),
                   help="report findings at or above this severity "
                        "(default: info, i.e. report everything)")
    args = p.parse_args(argv)

    if not os.path.exists(args.path):
        print(f"error: path not found: {args.path}", file=sys.stderr)
        return 2

    result = run(args.path, online=args.online,
                 show_unpinned=not args.no_unpinned,
                 min_severity=args.min_severity)

    if not result["files"]:
        print("error: no requirements.txt or package.json found.",
              file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        vulns = result["vulnerabilities"]
        print(f"[dependency-check] scanned {result['dependency_count']} "
              f"dependencies from {len(result['files'])} file(s)\n")
        if vulns:
            print(f"Known vulnerabilities ({len(vulns)}):")
            for v in vulns:
                via = f" (via {v['via']})" if v.get("via") else ""
                print(f"  [{v['severity'].upper():<8}] {v['package']} "
                      f"{v['version']}{via}  {v['id']}: {v['summary']}")
        else:
            print("No known vulnerabilities in the offline DB. [OK]")
        if result["unpinned"]:
            print(f"\nUnpinned dependencies ({len(result['unpinned'])}):")
            for w in result["unpinned"]:
                print(f"  - {w['package']} ({w['version']})")

    return 1 if result["vulnerabilities"] or result["unpinned"] else 0

if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    raise SystemExit(main())
