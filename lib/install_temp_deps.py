#!/usr/bin/env python3
"""
Temporary script to install Trivy and diffused-lib for local testing.
This will be removed once these tools are added to the container image.
"""

import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request


def install_trivy():
    """Install Trivy binary (simple version without hash verification)."""
    if shutil.which("trivy"):
        print("Trivy already installed", file=sys.stderr)
        return

    print("Installing Trivy...", file=sys.stderr)
    system = platform.system().lower()
    machine = platform.machine().lower()

    # Map architecture
    if machine in ["x86_64", "amd64"]:
        arch = "64bit"
    elif machine in ["aarch64", "arm64"]:
        arch = "ARM64"
    elif machine.startswith("arm"):
        arch = "ARM"
    else:
        arch = "64bit"

    # Map OS
    os_name = "Linux" if system == "linux" else "macOS"

    version = "0.67.2"
    filename = f"trivy_{version}_{os_name}-{arch}.tar.gz"
    url = f"https://github.com/aquasecurity/trivy/releases/download/v{version}/{filename}"

    print(f"Downloading Trivy from {url}...", file=sys.stderr)

    with tempfile.TemporaryDirectory() as tmpdir:
        archive_path = os.path.join(tmpdir, filename)
        urllib.request.urlretrieve(url, archive_path)

        with tarfile.open(archive_path, 'r:gz') as tar:
            tar.extractall(path=tmpdir)

        # Install to ~/.local/bin
        install_dir = os.path.expanduser("~/.local/bin")
        os.makedirs(install_dir, exist_ok=True)

        trivy_binary = os.path.join(tmpdir, "trivy")
        dest_path = os.path.join(install_dir, "trivy")
        shutil.copy2(trivy_binary, dest_path)
        os.chmod(dest_path, 0o755)

        print(f"Trivy installed to {dest_path}", file=sys.stderr)
        if install_dir not in os.environ.get("PATH", ""):
            print(f"Note: {install_dir} may not be in your PATH", file=sys.stderr)


def install_diffused():
    """Install diffused-lib Python package."""
    try:
        import diffused.differ
        print("diffused-lib already installed", file=sys.stderr)
        return
    except ImportError:
        pass

    print("Installing diffused-lib...", file=sys.stderr)
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "diffused-lib==0.2.0"],
        check=True,
        capture_output=True
    )
    print("diffused-lib installed successfully", file=sys.stderr)


if __name__ == "__main__":
    try:
        install_trivy()
        install_diffused()
        print("All dependencies installed successfully", file=sys.stderr)
    except Exception as e:
        print(f"Installation failed: {e}", file=sys.stderr)
        sys.exit(1)
