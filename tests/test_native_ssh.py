"""Exercise SSH option parsing without a device connection."""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import unittest
from pathlib import Path
from unittest import mock

path = Path(__file__).resolve().parents[1] / "credential-retrieval" / "native_ssh.py"
spec = importlib.util.spec_from_file_location("native_ssh", path)
assert spec is not None and spec.loader is not None
native_ssh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native_ssh)


class SSHTests(unittest.TestCase):
    def test_command_parses_on_host_without_connecting(self):
        if shutil.which("ssh") is None:
            self.skipTest("OpenSSH client unavailable")
        with (
            mock.patch.object(native_ssh.socket, "create_connection"),
            mock.patch.object(native_ssh.SSHDevice, "run", return_value=b""),
        ):
            device = native_ssh.SSHDevice(2222, "synthetic-device")
        result = subprocess.run(
            [device.command[0], "-F", "/dev/null", "-G", *device.command[1:]],
            capture_output=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn(b"hostname 127.0.0.1", result.stdout)


if __name__ == "__main__":
    unittest.main()
