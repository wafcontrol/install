"""Offline regression checks for versioned ModSecurity configuration setup."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "modules/waf-nginx.sh").read_text()
PREPARE = SOURCE[SOURCE.index("fetch_modsecurity_defaults() {"):SOURCE.index('MAIN="$MDIR/main.conf"')]
VALIDATE = SOURCE[SOURCE.index("validate_modsecurity_conf() {"):SOURCE.index("if ! validate_modsecurity_conf;")]

TEMPLATE = '''SecRuleEngine DetectionOnly
SecRequestBodyAccess On
SecUnicodeMapFile unicode.mapping 20127
SecRule MULTIPART_STRICT_ERROR "!@eq 0" \\
    "id:200003,phase:2,deny,status:400,msg:'Multipart validation: \\
DH %{MULTIPART_DUPLICATE_PART_HEADER}, \\
HF %{MULTIPART_HEADER_FOLDING}'"
'''


class ModSecurityConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.mdir = self.root / "modsec"
        self.mdir.mkdir()
        self.assets = self.root / "assets"
        self.assets.mkdir()
        # Old engine releases do not reference the new diagnostic variable.
        for version in ("3.0.12", "3.0.17"):
            release = self.assets / f"v{version}"
            release.mkdir()
            template = TEMPLATE if version == "3.0.17" else TEMPLATE.replace(
                "DH %{MULTIPART_DUPLICATE_PART_HEADER}, ", ""
            )
            (release / "modsecurity.conf-recommended").write_text(template)
            (release / "unicode.mapping").write_text("test mapping\n")

    def run_prepare(self, version="3.0.12", fail_asset="", timestamp="123"):
        preamble = r'''
set -euo pipefail
say() { :; }
err() { printf '%s\n' "$*" >&2; }
state_put_map() { printf '%s\n' "$*" >> "$TEST_ROOT/state.log"; }
curl() {
    local url="${@: -3:1}" target="${@: -1}" relative
    printf '%s\n' "$url" >> "$TEST_ROOT/requests.log"
    relative="${url#https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/}"
    [[ "${relative##*/}" != "$FAIL_ASSET" ]] || return 22
    cp "$TEST_ROOT/assets/$relative" "$target"
}
'''
        return subprocess.run(
            ["bash", "-c", preamble + PREPARE],
            env={**os.environ, "TEST_ROOT": str(self.root), "MDIR": str(self.mdir),
                 "MODSEC_VERSION": version, "TS": timestamp, "FAIL_ASSET": fail_asset},
            text=True, capture_output=True,
        )

    def test_fresh_install_uses_exact_v3_release_and_full_settings(self):
        result = self.run_prepare()
        self.assertEqual(result.returncode, 0, result.stderr)
        requests = (self.root / "requests.log").read_text().splitlines()
        self.assertEqual(requests, [
            f"https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v3.0.12/{asset}"
            for asset in ("modsecurity.conf-recommended", "unicode.mapping")
        ])
        config = (self.mdir / "modsecurity.conf").read_text()
        self.assertIn("SecRuleEngine On", config)
        self.assertIn("SecRequestBodyAccess On", config)
        self.assertIn("SecRule MULTIPART_STRICT_ERROR", config)
        self.assertIn(f"SecUnicodeMapFile {self.mdir}/unicode.mapping 20127", config)
        self.assertTrue((self.mdir / "unicode.mapping").exists())

    def test_failed_install_is_repaired_with_backup_and_local_settings_kept(self):
        original = TEMPLATE + "# Local setting\nSecRequestBodyLimit 987654\n"
        (self.mdir / "modsecurity.conf").write_text(original)
        (self.mdir / "unicode.mapping").write_text("existing mapping\n")
        result = self.run_prepare()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.mdir / "modsecurity.conf.bak.123").read_text(), original)
        config = (self.mdir / "modsecurity.conf").read_text()
        self.assertNotIn("%{MULTIPART_DUPLICATE_PART_HEADER}", config)
        self.assertIn("SecRule MULTIPART_STRICT_ERROR", config)
        self.assertIn("id:200003,phase:2,deny,status:400", config)
        self.assertIn("SecRequestBodyLimit 987654", config)
        self.assertIn("BACKUPS", (self.root / "state.log").read_text())
        self.assertFalse((self.root / "requests.log").exists())
        # A rerun must not replace the original backup or repeat the migration.
        again = self.run_prepare(timestamp="456")
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertEqual(list(self.mdir.glob("*.bak.*")), [self.mdir / "modsecurity.conf.bak.123"])

    def test_new_engine_keeps_supported_multipart_diagnostic(self):
        result = self.run_prepare(version="3.0.17")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("DH %{MULTIPART_DUPLICATE_PART_HEADER}",
                      (self.mdir / "modsecurity.conf").read_text())
        self.assertFalse(list(self.mdir.glob("*.bak.*")))

    def test_failed_download_leaves_no_partial_configuration_or_minimal_fallback(self):
        for asset in ("modsecurity.conf-recommended", "unicode.mapping"):
            with self.subTest(asset=asset):
                result = self.run_prepare(fail_asset=asset)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Cannot fetch", result.stderr)
                self.assertEqual(list(self.mdir.iterdir()), [])

    def test_missing_mapping_does_not_overwrite_existing_configuration(self):
        original = "SecRuleEngine On\nSecRequestBodyLimit 123456\n"
        (self.mdir / "modsecurity.conf").write_text(original)
        result = self.run_prepare()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.mdir / "modsecurity.conf").read_text(), original)
        self.assertTrue((self.mdir / "unicode.mapping").exists())

    def test_preflight_propagates_engine_failure_and_removes_temporary_files(self):
        script = r'''
set -euo pipefail
nginx() { printf '%s\n' "$*" > "$TEST_ROOT/preflight.log"; return 23; }
''' + VALIDATE + r'''
result=0
validate_modsecurity_conf || result=$?
exit "$result"
'''
        result = subprocess.run(
            ["bash", "-c", script],
            env={**os.environ, "TEST_ROOT": str(self.root), "MDIR": str(self.mdir),
                 "MOD_DIR": str(self.root), "TMPDIR": str(self.root)},
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 23, result.stderr)
        self.assertIn("-t -e stderr", (self.root / "preflight.log").read_text())
        self.assertFalse(list(self.root.glob("wafcontrol-nginx-check-*")))


class LocalModuleTests(unittest.TestCase):
    def test_checkout_uses_local_module_and_explicit_remote_override_is_respected(self):
        installer = (ROOT / "install.sh").read_text()
        initialize = installer[installer.index('LOCAL_MODULE_DIR=""'):installer.index('STATE_DIR=')]
        function = installer[installer.index("fetch_and_run() {"):installer.index("detect_os()")]
        with tempfile.TemporaryDirectory() as directory:
            modules = Path(directory, "modules")
            modules.mkdir()
            (modules / "example.sh").write_text("printf local-module")
            script = "set -euo pipefail\n" + initialize + r'''
banner() { :; }
curl() { printf 'printf remote-module'; }
''' + function + "\nfetch_and_run example.sh\n"
            entrypoint = Path(directory, "install.sh")
            entrypoint.write_text(script)
            env = {key: value for key, value in os.environ.items() if key != "MODULE_BASE"}
            for remote, expected in ((False, "local-module"), (True, "remote-module")):
                with self.subTest(remote=remote):
                    selected_env = {**env, "MODULE_BASE": "https://example.invalid/modules"} if remote else env
                    result = subprocess.run(["bash", str(entrypoint)], env=selected_env,
                                            capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout, expected)

    def test_stdin_installer_falls_back_to_remote_modules(self):
        installer = (ROOT / "install.sh").read_text()
        initialize = installer[installer.index('LOCAL_MODULE_DIR=""'):installer.index('STATE_DIR=')]
        function = installer[installer.index("fetch_and_run() {"):installer.index("detect_os()")]
        script = "set -euo pipefail\n" + initialize + r'''
banner() { :; }
curl() { printf 'printf remote-module'; }
''' + function + "\nfetch_and_run example.sh\n"
        env = {key: value for key, value in os.environ.items() if key != "MODULE_BASE"}
        result = subprocess.run(["bash", "-s"], input=script, env=env,
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "remote-module")


if __name__ == "__main__":
    unittest.main()
