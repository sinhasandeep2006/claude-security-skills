import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import checker

requires_tomllib = pytest.mark.skipif(
    sys.version_info < (3, 11),
    reason="tomllib is stdlib only on Python 3.11+",
)


def test_cmp():
    assert checker._cmp("1.2.3", "1.2.4") < 0
    assert checker._cmp("2.0.0", "1.9.9") > 0
    assert checker._cmp("1.0", "1.0.0") == 0


def test_version_matches():
    assert checker.version_matches("0.12.2", "<0.12.3")
    assert not checker.version_matches("0.12.3", "<0.12.3")
    assert checker.version_matches("1.0.0", "==1.0.0")
    assert checker.version_matches("2.0.0", ">=1.0.0")



@pytest.mark.parametrize("version,release", [
    ("1.2.3rc1", "1.2.3"),
    ("1.2.3-rc.1", "1.2.3"),
    ("2.0.0b1", "2.0.0"),
    ("1.2.3a1", "1.2.3"),
    ("1.2.3.dev1", "1.2.3"),
    ("1.2.3-beta", "1.2.3"),
    ("v0.3.1-0.20220314000000-abcdef123456", "v0.3.1"),
])
def test_prerelease_precedes_release(version, release):
    assert checker.version_matches(version, "<" + release)
    assert not checker.version_matches(version, ">=" + release)
    assert checker.version_matches(release, ">" + version)
    assert not checker.version_matches(version, "==" + release)


@pytest.mark.parametrize("older,newer", [
    ("1.2.3.dev1", "1.2.3a1"),
    ("1.2.3a1", "1.2.3b1"),
    ("1.2.3b1", "1.2.3rc1"),
    ("1.2.3rc2", "1.2.3rc10"),
    ("1.2.3rc1.dev1", "1.2.3rc1"),
    ("1.2.3-alpha", "1.2.3-beta"),
    ("1.2.3-rc.2", "1.2.3-rc.10"),
    ("1.2.3-1", "1.2.3-alpha"),
    ("v0.0.0-20201216223049-8b5274cf687f",
     "v0.0.0-20220314234659-1baeb1ce4c0b"),
])
def test_prerelease_ordering(older, newer):
    assert checker.version_matches(older, "<" + newer)
    assert checker.version_matches(newer, ">" + older)


def test_prerelease_uses_release_components_first():
    assert checker.version_matches("1.2.3rc1", ">1.2.2")
    assert checker.version_matches("1.2.3", "<1.2.4rc1")


def test_semver_build_metadata_does_not_change_precedence():
    assert checker.version_matches("1.2.3+build.99", "==1.2.3")
    assert checker.version_matches("1.2.3-rc.1+build.99", "==1.2.3-rc.1")


def test_offline_prerelease_vulnerability_and_fixed_release():
    for version in ("0.12.3rc1", "0.12.3.dev1"):
        findings = checker.check_offline(
            checker.parse_requirements("flask==" + version))
        assert any(f.id == "CVE-2018-1000656" for f in findings)
    assert checker.check_offline(checker.parse_requirements("flask==0.12.3")) == []


def test_parse_requirements_pinned():
    deps = checker.parse_requirements("flask==0.12.2\nrequests>=2.0\n# comment\n")
    flask = next(d for d in deps if d.name == "flask")
    assert flask.pinned and flask.version == "0.12.2"
    req = next(d for d in deps if d.name == "requests")
    assert not req.pinned


def test_parse_requirements_skips_blank_and_flags():
    deps = checker.parse_requirements("\n-r other.txt\n--index-url x\nflask==1.0\n")
    assert {d.name for d in deps} == {"flask"}


@requires_tomllib
def test_parse_pyproject_toml_dependencies():
    toml = """
    [project]
    dependencies = [
      "flask==2.0.0",
      "requests>=2.25",
      "pandas; python_version < '3.11'",
      "# ignored comment",
    ]
    """
    deps = checker.parse_pyproject_toml(toml)
    assert {d.name for d in deps} == {"flask", "requests", "pandas"}
    flask = next(d for d in deps if d.name == "flask")
    assert flask.pinned and flask.version == "2.0.0"
    requests = next(d for d in deps if d.name == "requests")
    assert not requests.pinned and requests.version == "2.25"
    pandas = next(d for d in deps if d.name == "pandas")
    assert not pandas.pinned and pandas.version is None


def test_parse_pyproject_toml_invalid_returns_empty():
    assert checker.parse_pyproject_toml("[not a valid toml") == []


def test_parse_package_json():
    pkg = json.dumps({
        "dependencies": {"lodash": "4.17.20", "axios": "^0.21.0"},
        "devDependencies": {"jest": "27.0.0"},
    })
    deps = checker.parse_package_json(pkg)
    names = {d.name for d in deps}
    assert {"lodash", "axios", "jest"} <= names
    lodash = next(d for d in deps if d.name == "lodash")
    assert lodash.pinned and lodash.version == "4.17.20"
    axios = next(d for d in deps if d.name == "axios")
    assert not axios.pinned


def test_parse_package_json_invalid():
    assert checker.parse_package_json("{not json") == []

def test_parse_go_mod_require_block():
    go_mod = """
    module example.com/myapp

    go 1.21

    require (
        github.com/gin-gonic/gin v1.9.0
        golang.org/x/crypto v0.14.0
    )
    """

    deps = checker.parse_go_mod(go_mod)

    assert len(deps) == 2

    gin = next(d for d in deps if d.name == "github.com/gin-gonic/gin")
    assert gin.ecosystem == "go"
    assert gin.version == "v1.9.0"
    assert gin.pinned

    crypto = next(d for d in deps if d.name == "golang.org/x/crypto")
    assert crypto.version == "v0.14.0"
    assert crypto.pinned

def test_parse_go_mod_single_require():
    go_mod = """
    module example.com/myapp

    go 1.21

    require github.com/gin-gonic/gin v1.9.0
    """

    deps = checker.parse_go_mod(go_mod)

    assert len(deps) == 1

    gin = deps[0]
    assert gin.ecosystem == "go"
    assert gin.name == "github.com/gin-gonic/gin"
    assert gin.version == "v1.9.0"
    assert gin.pinned

def test_parse_go_mod_skips_indirect_dependencies():
    go_mod = """
    module example.com/myapp

    require (
        github.com/gin-gonic/gin v1.9.0
        golang.org/x/crypto v0.14.0 // indirect
    )

    require github.com/stretchr/testify v1.8.4 // indirect
    """

    deps = checker.parse_go_mod(go_mod)

    assert len(deps) == 1
    assert deps[0].name == "github.com/gin-gonic/gin"

def test_parse_go_mod_pseudo_version():
    go_mod = """
    require (
        golang.org/x/example v0.0.0-20191109021931-daa7c04131f5
    )
    """

    deps = checker.parse_go_mod(go_mod)

    assert len(deps) == 1
    assert deps[0].name == "golang.org/x/example"
    assert deps[0].version == "v0.0.0-20191109021931-daa7c04131f5"
    assert deps[0].pinned

def test_go_pseudo_version_comparison():
    pseudo = "v0.0.0-20191109021931-daa7c04131f5"

    assert checker.version_matches(pseudo, "<v0.0.1")

def test_run_directory_with_go_mod(tmp_path):
    (tmp_path / "go.mod").write_text(
        """
        module example.com/myapp

        go 1.21

        require (
            github.com/gin-gonic/gin v1.9.0
        )
        """
    )

    result = checker.run(str(tmp_path))

    assert result["dependency_count"] == 1
    assert len(result["files"]) == 1
    assert result["files"][0].endswith("go.mod")

def test_vulnerable_go_dependency_detected():
    deps = checker.parse_go_mod(
        """
        require (
            golang.org/x/crypto v0.0.0-20201216223049-8b5274cf687f
        )
        """
    )

    findings = checker.check_offline(deps)

    assert any(f.id == "CVE-2022-27191" for f in findings)

def test_parse_go_mod_skips_comments():
    go_mod = """
    require (
        // Direct dependencies
        github.com/gin-gonic/gin v1.9.0
    )
    """

    deps = checker.parse_go_mod(go_mod)

    assert len(deps) == 1
    assert deps[0].name == "github.com/gin-gonic/gin"
    
def test_safe_go_dependency_not_detected():
    deps = checker.parse_go_mod(
        """
        require (
            golang.org/x/crypto v0.17.0
        )
        """
    )

    findings = checker.check_offline(deps)

    assert not any(f.id == "CVE-2022-27191" for f in findings)

def test_vulnerable_flask_detected():
    deps = checker.parse_requirements("flask==0.12.2\n")
    findings = checker.check_offline(deps)
    assert any(f.id == "CVE-2018-1000656" for f in findings)


def test_patched_flask_not_detected():
    deps = checker.parse_requirements("flask==1.0.0\n")
    assert checker.check_offline(deps) == []


def test_vulnerable_lodash_detected():
    deps = checker.parse_package_json(
        json.dumps({"dependencies": {"lodash": "4.17.20"}}))
    findings = checker.check_offline(deps)
    assert any(f.id == "CVE-2021-23337" for f in findings)


def test_findings_sorted_by_severity():
    deps = checker.parse_requirements("django==2.0.0\njinja2==2.10.0\n")
    findings = checker.check_offline(deps)
    ranks = [checker.SEV_RANK[f.severity] for f in findings]
    assert ranks == sorted(ranks)


def test_unpinned_warnings():
    deps = checker.parse_requirements("requests>=2.0\nflask==1.0\n")
    warns = checker.unpinned_warnings(deps)
    assert any(w.package == "requests" for w in warns)
    assert not any(w.package == "flask" for w in warns)


def test_run_directory(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==0.12.2\n")
    result = checker.run(str(tmp_path))
    assert result["dependency_count"] == 1
    assert result["vulnerabilities"]


@requires_tomllib
def test_run_directory_with_pyproject_toml(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        """
        [project]
        dependencies = ["flask==0.12.2"]
        """
    )
    result = checker.run(str(tmp_path))
    assert result["dependency_count"] == 1
    assert len(result["vulnerabilities"]) == 1


def test_cli_exit_code_vuln(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_text("flask==0.12.2\n")
    assert checker.main([str(f)]) == 1


def test_cli_exit_code_clean(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_text("flask==2.0.0\n")
    assert checker.main([str(f)]) == 0


def test_cli_no_manifest(tmp_path):
    assert checker.main([str(tmp_path)]) == 2


def test_cli_json(tmp_path, capsys):
    f = tmp_path / "requirements.txt"
    f.write_text("flask==0.12.2\n")
    checker.main([str(f), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["vulnerabilities"]


def test_cli_unpinned_only_exits_one(tmp_path):
    """Unpinned deps are reported, so they must fail the build (issue #46)."""
    f = tmp_path / "requirements.txt"
    f.write_text("httpx\nrich>=13.0\n")
    assert checker.main([str(f)]) == 1


def test_cli_no_unpinned_suppresses_report_and_exit(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_text("httpx\nrich>=13.0\n")
    assert checker.main([str(f), "--no-unpinned"]) == 0


def test_cli_min_severity_filters_report_and_exit(tmp_path, capsys):
    f = tmp_path / "requirements.txt"
    f.write_text("httpx\nrich>=13.0\n")
    rc = checker.main([str(f), "--min-severity", "medium", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["unpinned"] == [] and data["vulnerabilities"] == []
    assert rc == 0


def test_run_min_severity_filters_vulnerabilities(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_text("jinja2==2.11.0\n")  # medium-severity advisory
    assert checker.run(str(f))["vulnerabilities"]
    assert checker.run(str(f), min_severity="high")["vulnerabilities"] == []


# --- lockfiles (#53) ---------------------------------------------------------

LOCK_V3 = json.dumps({
    "lockfileVersion": 3,
    "packages": {
        "": {"name": "app", "dependencies": {"webpack": "^5.0.0"},
             "devDependencies": {"axios": "^1.0.0"}},
        "node_modules/webpack": {"version": "5.0.0",
                                 "dependencies": {"terser": "^5.0.0"}},
        "node_modules/terser": {"version": "5.0.0",
                                "dependencies": {"lodash": "^4.17.0"}},
        # hoisted: the path alone says nothing about who pulled it in
        "node_modules/lodash": {"version": "4.17.15"},
        # nested copy that webpack resolves before the hoisted one
        "node_modules/webpack/node_modules/minimist": {"version": "1.2.5"},
        "node_modules/axios": {"version": "1.6.0"},
        "node_modules/@scope/pkg": {"version": "1.0.0"},
    },
})


def test_package_lock_v3_reports_transitive_chain():
    deps = {d.name: d for d in checker.parse_package_lock(LOCK_V3)}
    assert deps["lodash"].version == "4.17.15"
    assert deps["lodash"].via == "webpack > terser"
    assert deps["minimist"].via == "webpack"
    assert deps["webpack"].via is None and deps["axios"].via is None
    assert deps["@scope/pkg"].version == "1.0.0"
    assert all(d.pinned for d in deps.values())
    lodash = next(f for f in checker.check_offline(list(deps.values()))
                  if f.package == "lodash")
    assert lodash.id == "CVE-2021-23337" and lodash.via == "webpack > terser"


def test_package_lock_nested_version_resolves_before_hoisted():
    lock = json.dumps({"packages": {
        "": {"dependencies": {"webpack": "*", "lodash": "*"}},
        "node_modules/webpack": {"version": "5.0.0",
                                 "dependencies": {"lodash": "*"}},
        "node_modules/webpack/node_modules/lodash": {"version": "4.17.15"},
        "node_modules/lodash": {"version": "4.17.21"},
    }})
    findings = checker.check_offline(checker.parse_package_lock(lock))
    assert [(f.version, f.via) for f in findings] == [("4.17.15", "webpack")]


def test_package_lock_v1_dependencies_shape():
    lock = json.dumps({"lockfileVersion": 1, "dependencies": {
        "webpack": {"version": "4.0.0", "requires": {"terser": "^4"}},
        "terser": {"version": "4.0.0", "requires": {"lodash": "^4"},
                   "dependencies": {
                       "lodash": {"version": "4.17.15"}}},
        "lodash": {"version": "4.17.21"},
    }})
    deps = checker.parse_package_lock(lock)
    vulnerable = [d for d in deps if (d.name, d.version) == ("lodash", "4.17.15")]
    assert [d.via for d in vulnerable] == ["webpack > terser"]
    assert next(d for d in deps if d.name == "webpack").via is None


def test_package_lock_invalid_returns_empty():
    assert checker.parse_package_lock("{not json") == []


POETRY_LOCK = '''
[[package]]
name = "Flask"
version = "0.12.2"
description = "A simple framework"
optional = false

[package.dependencies]
Jinja2 = ">=2.4"
click = ">=2.0"

[package.extras]
dotenv = ["python-dotenv"]

[[package]]
name = "jinja2"
version = "2.10.0"

[package.dependencies]
MarkupSafe = ">=0.23"

[[package]]
name = "markupsafe"
version = "2.0.0"

[metadata]
lock-version = "2.0"
python-versions = "^3.9"
'''


def _check_poetry(deps):
    by_name = {d.name: d for d in deps}
    assert set(by_name) == {"flask", "jinja2", "markupsafe"}
    assert by_name["flask"].via is None
    assert by_name["jinja2"].via == "flask"
    assert by_name["markupsafe"].via == "flask > jinja2"
    ids = {f.id: f.via for f in checker.check_offline(deps)}
    assert ids == {"CVE-2018-1000656": None, "CVE-2020-28493": "flask"}


def test_parse_poetry_lock():
    _check_poetry(checker.parse_poetry_lock(POETRY_LOCK))


def test_parse_poetry_lock_without_tomllib(monkeypatch):
    # The built-in reader is what Python 3.9/3.10 use.
    monkeypatch.setitem(sys.modules, "tomllib", None)
    _check_poetry(checker.parse_poetry_lock(POETRY_LOCK))


def test_lockfile_wins_over_manifest(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"webpack": "^5.0.0"},
                    "devDependencies": {"axios": "^1.0.0"}}))
    (tmp_path / "package-lock.json").write_text(LOCK_V3)
    result = checker.run(str(tmp_path))
    assert [os.path.basename(f) for f in result["files"]] == ["package-lock.json"]
    names = [v["package"] for v in result["vulnerabilities"]]
    assert len(names) == len(set(names))
    assert result["unpinned"] == []  # lockfile versions are exact


def test_poetry_lock_dedupes_requirements(tmp_path):
    (tmp_path / "poetry.lock").write_text(POETRY_LOCK)
    (tmp_path / "pyproject.toml").write_text(
        '[project]\ndependencies = ["flask>=0.12"]\n')
    (tmp_path / "requirements.txt").write_text("flask==0.12.2\nrequests>=2\n")
    result = checker.run(str(tmp_path))
    names = sorted(os.path.basename(f) for f in result["files"])
    assert names == ["poetry.lock", "requirements.txt"]
    flask = [v for v in result["vulnerabilities"] if v["package"] == "flask"]
    assert len(flask) == 1
    assert result["dependency_count"] == 4  # 3 locked + requests


def test_cli_text_shows_via(tmp_path, capsys):
    (tmp_path / "package-lock.json").write_text(LOCK_V3)
    assert checker.main([str(tmp_path)]) == 1
    assert "lodash 4.17.15 (via webpack > terser)" in capsys.readouterr().out


def test_online_osv_batches_queries(monkeypatch):
    calls = []

    def fake_osv(url, body=None, timeout=10.0):
        calls.append(url)
        if url.endswith("querybatch"):
            return {"results": [
                {"vulns": [{"id": "GHSA-1"}]} if q["package"]["name"] == "pkg7"
                else {} for q in body["queries"]]}
        return {"id": "GHSA-1", "summary": "bad",
                "database_specific": {"severity": "HIGH"}}

    monkeypatch.setattr(checker, "_osv", fake_osv)
    deps = [checker.Dep("npm", f"pkg{i % 10}", "1.0.0", "", True, "root")
            for i in range(2500)]
    findings = checker.check_online_osv(deps)
    assert calls.count("https://api.osv.dev/v1/querybatch") == 3
    assert calls.count("https://api.osv.dev/v1/vulns/GHSA-1") == 1
    assert len(findings) == 250
    assert findings[0].severity == "high" and findings[0].via == "root"
