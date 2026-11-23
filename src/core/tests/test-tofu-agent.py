#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

BUS_NAME = "org.freedesktop.NetworkManager"
AGENT_MANAGER_PATH = "/org/freedesktop/NetworkManager/AgentManager"
AGENT_MANAGER_IFACE = BUS_NAME + ".AgentManager"
WIFI_TOFU_CAPABILITY = 0x2


def run(*args, check=True):
    return subprocess.run(
        args,
        check=check,
        stdout=subprocess.PIPE,
        stderr=None if check else subprocess.PIPE,
        text=True,
        timeout=25,
    )


def test_agent_registration(daemon_path):
    import gi

    gi.require_version("Gio", "2.0")
    from gi.repository import Gio, GLib

    if os.geteuid() != 0:
        raise SystemExit("ERROR: --inside must run as root in the bwrap sandbox")
    if os.environ.get("NM_TEST_HOST_NETNS") in (None, os.readlink("/proc/self/ns/net")):
        raise SystemExit("ERROR: --inside must run in the bwrap sandbox")

    os.environ["DBUS_SYSTEM_BUS_ADDRESS"] = os.environ["DBUS_SESSION_BUS_ADDRESS"]
    os.environ["G_DEBUG"] = "fatal-warnings"
    os.environ["LC_ALL"] = "C"

    root = Path(tempfile.mkdtemp(prefix="tofu-agent-test-"))
    (root / "connections").mkdir(parents=True)
    (root / "conf.d").mkdir()
    (root / "NetworkManager.conf").write_text(
        "[main]\nplugins=keyfile\nauth-polkit=root-only\ndns=none\n"
        "rc-manager=unmanaged\nhostname-mode=none\nno-auto-default=*\n"
        f"[keyfile]\npath={root}/connections\n"
        "unmanaged-devices=*\n"
        "[connectivity]\ninterval=0\n"
    )

    bus = Gio.DBusConnection.new_for_address_sync(
        os.environ["DBUS_SYSTEM_BUS_ADDRESS"],
        Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT
        | Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION,
        None,
        None,
    )

    def call(method, signature, args, timeout=10000):
        return bus.call_sync(
            BUS_NAME,
            AGENT_MANAGER_PATH,
            AGENT_MANAGER_IFACE,
            method,
            GLib.Variant(signature, args),
            None,
            Gio.DBusCallFlags.NONE,
            timeout,
            None,
        )

    with (root / "daemon.log").open("w") as log:
        daemon = subprocess.Popen(
            [
                daemon_path,
                "--debug",
                "--run-from-build-dir",
                f"--config={root}/NetworkManager.conf",
                f"--config-dir={root}/conf.d",
                "--system-config-dir=",
                f"--intern-config={root}/intern.conf",
                f"--state-file={root}/state",
                f"--no-auto-default={root}/no-auto-default",
                f"--pid-file={root}/nm.pid",
            ],
            stdout=log,
            stderr=log,
        )

        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if daemon.poll() is not None:
                    raise AssertionError(f"NetworkManager exited with {daemon.returncode}")
                try:
                    if bus.call_sync(
                        "org.freedesktop.DBus",
                        "/org/freedesktop/DBus",
                        "org.freedesktop.DBus",
                        "NameHasOwner",
                        GLib.Variant("(s)", (BUS_NAME,)),
                        GLib.VariantType.new("(b)"),
                        Gio.DBusCallFlags.NONE,
                        1000,
                        None,
                    ).unpack()[0]:
                        break
                except GLib.Error:
                    pass
                time.sleep(0.05)
            else:
                raise AssertionError("NetworkManager did not acquire its D-Bus name")

            call(
                "RegisterWithCapabilities",
                "(su)",
                ("test-tofu-agent", WIFI_TOFU_CAPABILITY),
            )

            try:
                call(
                    "RegisterWithCapabilities",
                    "(su)",
                    ("test-tofu-agent", WIFI_TOFU_CAPABILITY),
                )
            except GLib.Error as error:
                if "already registered" not in error.message.lower():
                    raise
            else:
                raise AssertionError("duplicate agent identifier was accepted")

            call("Unregister", "()", ())
        except BaseException:
            log.flush()
            print((root / "daemon.log").read_text())
            raise
        finally:
            daemon.terminate()
            try:
                daemon.wait(timeout=5)
            except subprocess.TimeoutExpired:
                daemon.kill()
                daemon.wait()
            bus.close_sync(None)
            shutil.rmtree(root)


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--inside":
        return test_agent_registration(sys.argv[2])

    for program in ("bwrap", "dbus-run-session"):
        if not shutil.which(program):
            print(f"SKIP: required program {program} is unavailable")
            return 77
    try:
        import gi
    except ImportError:
        print("SKIP: Python GObject introspection is unavailable")
        return 77

    probe = run(
        "bwrap",
        "--unshare-all",
        "--uid",
        "0",
        "--gid",
        "0",
        "--ro-bind",
        "/",
        "/",
        "true",
        check=False,
    )
    if probe.returncode:
        print(f"SKIP: isolated namespaces unavailable: {probe.stderr.strip()}")
        return 77

    daemon_path, state_dir, run_dir = sys.argv[1:]
    source_root = Path(__file__).resolve().parents[3]
    build_root = Path(daemon_path).resolve().parents[2]
    mounts = set()
    for path in map(Path, (state_dir, run_dir)):
        if path.parts[1] in ("run", "var", "tmp"):
            continue
        while not path.exists():
            path = path.parent
        if source_root.is_relative_to(path) or build_root.is_relative_to(path):
            print(f"SKIP: cannot make {state_dir} and {run_dir} writable")
            return 77
        mounts.add(path)

    os.environ["NM_TEST_HOST_NETNS"] = os.readlink("/proc/self/ns/net")
    sandbox = [
        "bwrap",
        "--unshare-all",
        "--uid",
        "0",
        "--gid",
        "0",
        "--die-with-parent",
        "--cap-drop",
        "ALL",
        "--ro-bind",
        "/",
        "/",
        "--tmpfs",
        "/run",
        "--tmpfs",
        "/var",
        "--tmpfs",
        "/tmp",
        "--ro-bind",
        str(source_root),
        str(source_root),
        "--ro-bind",
        str(build_root),
        str(build_root),
    ]
    for path in sorted(mounts):
        sandbox += ["--tmpfs", str(path)]
    sandbox += ["--dir", state_dir, "--dir", run_dir, "--proc", "/proc", "--dev", "/dev"]
    for name in (
        "DBUS_SYSTEM_BUS_ADDRESS",
        "DBUS_SESSION_BUS_ADDRESS",
        "XDG_RUNTIME_DIR",
        "LD_PRELOAD",
        "PYTHONOPTIMIZE",
    ):
        sandbox += ["--unsetenv", name]

    return subprocess.run(
        sandbox
        + [
            "dbus-run-session",
            "--",
            sys.executable,
            str(Path(__file__).resolve()),
            "--inside",
            daemon_path,
        ],
        timeout=60,
    ).returncode


if __name__ == "__main__":
    sys.exit(main())
