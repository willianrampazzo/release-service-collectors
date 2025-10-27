#!/usr/bin/env python
"""
SBOM Diff Collector for Release Service

This script compares Software Bill of Materials (SBOMs) between consecutive releases
to identify changes in vulnerabilities. It retrieves container images from Kubernetes
snapshots, downloads their SBOMs using cosign, and uses Trivy + diffused-lib to
analyze vulnerability differences.

Usage:
    python lib/sbomdiff.py --release release.json --previousRelease previous_release.json
    python lib/sbomdiff.py tenant --release release.json --previousRelease previous_release.json
    python lib/sbomdiff.py managed --release release.json --previousRelease previous_release.json

Arguments:
    mode                    (Optional) Either 'tenant' or 'managed' (currently has no impact)
    --release, -r          Path to current release JSON file
    --previousRelease, -p  Path to previous release JSON file

Input Format (release.json):
    {
        "metadata": {
            "namespace": "my-namespace"
        },
        "spec": {
            "snapshot": "snapshot-name"
        }
    }

Output Format:
    {
        "releaseNotes": {
            "sbomDiff": {
                "component-name": {
                    "status": "compared",  # or "new" or "error"
                    "vulnerabilities_removed": [...],
                    "vulnerabilities_removed_details": [...],
                    "current_image": "registry/image:tag@sha256:...",
                    "previous_image": "registry/image:tag@sha256:..."
                }
            }
        }
    }

    Status values:
        - "compared": Successfully compared SBOMs between releases
        - "new": Component is new in this release (no previous version)
        - "error": Failed to process component (see "reason" field)

Dependencies:
    - kubectl: Must be available in PATH and configured with cluster access
    - cosign: Must be available in PATH for downloading SBOMs
    - trivy: Will be automatically installed if not found (version 0.67.2)
    - diffused-lib: Will be automatically installed if not found (version 0.2.0)

Example:
    python lib/sbomdiff.py tenant \\
        --release /path/to/current-release.json \\
        --previousRelease /path/to/previous-release.json

Exit Codes:
    0 - Success: SBOM comparison completed successfully
    1 - Expected error: Invalid input, missing files, or known failure conditions
    2 - Unexpected error: Unhandled exception occurred (includes stack trace)
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from typing import Optional, Dict, Any, List, Tuple


class ExternalCommands:
    """
    Wrapper for external command execution to enable testing.

    This class encapsulates all external command calls (kubectl, cosign, trivy)
    to make the code testable by allowing these dependencies to be mocked.
    """

    def run_kubectl(self, args: List[str]) -> str:
        """
        Execute kubectl command.

        Args:
            args: List of arguments to pass to kubectl

        Returns:
            str: stdout from kubectl command

        Raises:
            subprocess.CalledProcessError: If kubectl command fails
        """
        cmd = ["kubectl"] + args
        log(f"Running {' '.join(cmd)}")
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        return result.stdout

    def run_cosign(self, args: List[str]) -> str:
        """
        Execute cosign command.

        Args:
            args: List of arguments to pass to cosign

        Returns:
            str: stdout from cosign command

        Raises:
            subprocess.CalledProcessError: If cosign command fails
        """
        cmd = ["cosign"] + args
        log(f"Running {' '.join(cmd)}")
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        return result.stdout

    def check_command_available(self, command: str, version_flag: str = "--version") -> Tuple[bool, Optional[str]]:
        """
        Check if a command is available in PATH.

        Args:
            command: Command name to check
            version_flag: Flag to use for version check (default: --version)

        Returns:
            tuple: (is_available: bool, version_output: str or None)
        """
        try:
            result = subprocess.run(
                [command, version_flag],
                capture_output=True,
                text=True,
                check=True
            )
            return True, result.stdout.strip()
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False, None

    def run_pip_install(self, package: str) -> str:
        """
        Install a Python package using pip.

        Args:
            package: Package specification (e.g., "package==1.0.0")

        Returns:
            str: stdout from pip install

        Raises:
            subprocess.CalledProcessError: If pip install fails
        """
        cmd = [sys.executable, "-m", "pip", "install", package]
        log(f"Running {' '.join(cmd)}")
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        return result.stdout


def log(message: str) -> None:
    """
    Log a message to stderr.

    Args:
        message: The message to log
    """
    print(message, file=sys.stderr)


def read_json(file: str) -> Optional[Any]:
    """
    Read JSON data from a file.

    Args:
        file: Path to the JSON file

    Returns:
        Parsed JSON data as a Python dict/list, or None if file is empty

    Raises:
        json.JSONDecodeError: If file contains invalid JSON
        OSError: If file cannot be read
    """
    if os.path.getsize(file) > 0:
        with open(file, 'r') as f:
            data = json.load(f)
        return data
    return None


def validate_container_image(container_image: Any, component_name: str, context: str) -> Optional[Dict[str, str]]:
    """
    Validate a containerImage field and return error information if invalid.

    Args:
        container_image: The containerImage value to validate
        component_name: Name of the component (for logging)
        context: Context string (e.g., "current release", "previous release")

    Returns:
        dict or None: Error dict with status and reason if invalid, None if valid

    Example:
        >>> validate_container_image(None, "my-app", "current release")
        {'status': 'error', 'reason': 'no containerImage in current release'}

        >>> validate_container_image("registry/image:v1", "my-app", "current release")
        None
    """
    if not container_image:
        log(f"WARNING: No containerImage found for component {component_name} in {context}")
        return {
            "status": "error",
            "reason": f"no containerImage in {context}"
        }

    if not isinstance(container_image, str) or not container_image.strip():
        log(f"WARNING: Invalid containerImage for component {component_name} in {context}: {container_image}")
        return {
            "status": "error",
            "reason": "invalid containerImage (must be non-empty string)"
        }

    return None


def get_snapshot_name(data_release: Dict[str, Any]) -> str:
    """
    Extract the snapshot name from release data.

    Args:
        data_release: Parsed release JSON data containing spec.snapshot

    Returns:
        str: The snapshot name

    Raises:
        ValueError: If 'spec' or 'snapshot' keys are missing, or if values are invalid
    """
    if "spec" not in data_release:
        raise ValueError(f"Missing 'spec' key in release data: {data_release}")

    spec = data_release["spec"]
    if not isinstance(spec, dict):
        raise ValueError(f"'spec' must be a dictionary, got {type(spec).__name__}: {spec}")

    if "snapshot" not in spec:
        raise ValueError(f"Missing 'snapshot' key in spec: {spec}")

    snapshot = spec["snapshot"]
    if not isinstance(snapshot, str):
        raise ValueError(f"'snapshot' must be a string, got {type(snapshot).__name__}: {snapshot}")

    if not snapshot.strip():
        raise ValueError(f"'snapshot' cannot be empty or whitespace: '{snapshot}'")

    return snapshot


def get_snapshot_namespace(data_release: Dict[str, Any]) -> str:
    """
    Extract the namespace from release data.

    Args:
        data_release: Parsed release JSON data containing metadata.namespace

    Returns:
        str: The namespace name

    Raises:
        ValueError: If 'metadata' or 'namespace' keys are missing, or if values are invalid
    """
    if "metadata" not in data_release:
        raise ValueError(f"Missing 'metadata' key in release data: {data_release}")

    metadata = data_release["metadata"]
    if not isinstance(metadata, dict):
        raise ValueError(f"'metadata' must be a dictionary, got {type(metadata).__name__}: {metadata}")

    if "namespace" not in metadata:
        raise ValueError(f"Missing 'namespace' key in metadata: {metadata}")

    namespace = metadata["namespace"]
    if not isinstance(namespace, str):
        raise ValueError(f"'namespace' must be a string, got {type(namespace).__name__}: {namespace}")

    if not namespace.strip():
        raise ValueError(f"'namespace' cannot be empty or whitespace: '{namespace}'")

    return namespace


def get_snapshot_data(namespace: str, snapshot: str, cmd_runner: Optional[ExternalCommands] = None) -> Dict[str, Any]:
    """
    Retrieve snapshot data from Kubernetes using kubectl.

    Args:
        namespace: Kubernetes namespace containing the snapshot
        snapshot: Name of the snapshot resource
        cmd_runner: ExternalCommands instance for running kubectl (defaults to new instance)

    Returns:
        dict: Parsed snapshot JSON data from Kubernetes

    Raises:
        subprocess.CalledProcessError: If kubectl command fails
        json.JSONDecodeError: If kubectl output is not valid JSON
    """
    if cmd_runner is None:
        cmd_runner = ExternalCommands()

    try:
        output = cmd_runner.run_kubectl(["get", "snapshot", snapshot, "-n", namespace, "-ojson"])
        log(f"Retrieved snapshot {snapshot} successfully ({len(output)} bytes)")
        return json.loads(output)
    except subprocess.CalledProcessError as e:
        log(f"kubectl command failed: {e}")
        raise
    except json.JSONDecodeError as e:
        log(f"Failed to parse JSON output from kubectl: {e}")
        raise
    except Exception as e:
        log(f"Unknown error occurred: {e}")
        raise


def install_trivy() -> None:
    """
    Install Trivy binary from GitHub releases with SHA256 verification.

    Downloads the appropriate Trivy binary for the current platform, fetches the
    official checksums file from GitHub releases, verifies the SHA256 checksum,
    and installs it to a directory in PATH.

    Supported platforms:
        - Linux: x86_64, ARM64, ARM (32-bit)
        - macOS: x86_64 (Intel), ARM64 (Apple Silicon)

    Raises:
        RuntimeError: If platform is unsupported, checksum verification fails,
                     or installation fails
        urllib.error.URLError: If download fails
    """
    import platform
    import urllib.request
    import tarfile
    import shutil
    import hashlib

    log("Installing Trivy...")

    # Determine the system architecture and OS
    system = platform.system().lower()
    machine = platform.machine().lower()

    # Map machine architecture to Trivy's naming convention
    # Trivy releases use: 64bit (x86_64), ARM64 (aarch64), ARM (32-bit arm)
    if machine == "x86_64" or machine == "amd64":
        arch = "64bit"
    elif machine == "aarch64" or machine == "arm64":
        arch = "ARM64"
    elif machine.startswith("arm") or machine == "armv7l":
        arch = "ARM"
    else:
        log(f"Unsupported architecture: {machine}")
        raise RuntimeError(f"Unsupported architecture: {machine}")

    # Map system to Trivy's naming convention
    if system == "linux":
        os_name = "Linux"
    elif system == "darwin":
        os_name = "macOS"
    else:
        log(f"Unsupported operating system: {system}")
        raise RuntimeError(f"Unsupported operating system: {system}")

    # Trivy version
    trivy_version = "0.67.2"
    filename = f"trivy_{trivy_version}_{os_name}-{arch}.tar.gz"

    # Download and parse official checksums file
    checksums_url = f"https://github.com/aquasecurity/trivy/releases/download/v{trivy_version}/trivy_{trivy_version}_checksums.txt"
    log(f"Fetching official checksums from {checksums_url}")

    try:
        with urllib.request.urlopen(checksums_url) as response:
            checksums_content = response.read().decode('utf-8')
    except Exception as e:
        log(f"Failed to fetch checksums file: {e}")
        raise RuntimeError(f"Failed to fetch official checksums from {checksums_url}: {e}")

    # Parse checksums file (format: "checksum  filename")
    checksums = {}
    for line in checksums_content.strip().split('\n'):
        if line.strip():
            parts = line.split()
            if len(parts) >= 2:
                checksum = parts[0]
                # Filename might have spaces, so join remaining parts
                file_name = ' '.join(parts[1:])
                checksums[file_name] = checksum

    expected_checksum = checksums.get(filename)
    if not expected_checksum:
        log(f"No checksum found for {filename} in official checksums file")
        log(f"Available checksums: {list(checksums.keys())}")
        raise RuntimeError(f"No checksum available for {filename}")

    log(f"Found checksum for {filename}: {expected_checksum}")

    url = f"https://github.com/aquasecurity/trivy/releases/download/v{trivy_version}/{filename}"

    log(f"Downloading Trivy from {url}")

    try:
        # Create a temporary directory for download
        with tempfile.TemporaryDirectory() as tmpdir:
            archive_path = os.path.join(tmpdir, filename)

            # Download the archive
            urllib.request.urlretrieve(url, archive_path)
            log(f"Downloaded Trivy archive to {archive_path}")

            # Verify SHA256 checksum
            log("Verifying SHA256 checksum...")
            sha256_hash = hashlib.sha256()
            with open(archive_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            actual_checksum = sha256_hash.hexdigest()

            if actual_checksum != expected_checksum:
                log(f"ERROR: Checksum verification failed!")
                log(f"Expected: {expected_checksum}")
                log(f"Actual:   {actual_checksum}")
                raise RuntimeError("Trivy archive checksum verification failed")

            log(f"Checksum verified: {actual_checksum}")

            # Extract the archive
            with tarfile.open(archive_path, 'r:gz') as tar:
                tar.extractall(path=tmpdir)
            log("Extracted Trivy archive")

            # Find a suitable installation directory in PATH
            trivy_binary = os.path.join(tmpdir, "trivy")
            install_dir = None

            # Try to install to a user-writable location in PATH
            path_dirs = os.environ.get('PATH', '').split(os.pathsep)
            user_home = os.path.expanduser("~")

            # Prefer ~/.local/bin if it exists or can be created
            local_bin = os.path.join(user_home, ".local", "bin")
            if os.path.exists(local_bin) or local_bin in path_dirs:
                if not os.path.exists(local_bin):
                    os.makedirs(local_bin, exist_ok=True)
                install_dir = local_bin
            else:
                # Try to find a writable directory in PATH
                for path_dir in path_dirs:
                    if os.path.exists(path_dir) and os.access(path_dir, os.W_OK):
                        install_dir = path_dir
                        break

            if not install_dir:
                # Fallback to ~/.local/bin even if not in PATH
                install_dir = local_bin
                os.makedirs(install_dir, exist_ok=True)
                log(f"Warning: {install_dir} is not in PATH, you may need to add it")

            # Copy trivy binary to installation directory
            dest_path = os.path.join(install_dir, "trivy")
            shutil.copy2(trivy_binary, dest_path)
            os.chmod(dest_path, 0o755)

            log(f"Trivy installed successfully to {dest_path}")

    except Exception as e:
        log(f"Failed to install Trivy: {e}")
        raise


def install_diffused_lib(cmd_runner: Optional[ExternalCommands] = None) -> None:
    """
    Install diffused-lib package using pip with pinned version.

    Installs diffused-lib version 0.2.0 using pip. This library is used
    for comparing SBOMs and analyzing vulnerability differences.

    Args:
        cmd_runner: ExternalCommands instance for running pip (defaults to new instance)

    Raises:
        subprocess.CalledProcessError: If pip installation fails
    """
    if cmd_runner is None:
        cmd_runner = ExternalCommands()

    diffused_version = "0.2.0"
    log(f"Installing diffused-lib=={diffused_version}...")
    try:
        output = cmd_runner.run_pip_install(f"diffused-lib=={diffused_version}")
        log(f"diffused-lib=={diffused_version} installed successfully")
    except subprocess.CalledProcessError as e:
        log(f"Failed to install diffused-lib=={diffused_version}: {e.stderr}")
        raise
    except Exception as e:
        log(f"Unknown error occurred during package installation: {e}")
        raise


def get_components_from_snapshot(namespace: str, snapshot_name: str, cmd_runner: Optional[ExternalCommands] = None) -> List[Dict[str, Any]]:
    """
    Retrieve the list of components from a Kubernetes snapshot.

    Args:
        namespace: Kubernetes namespace containing the snapshot
        snapshot_name: Name of the snapshot resource
        cmd_runner: ExternalCommands instance for running kubectl (defaults to new instance)

    Returns:
        list: List of component dictionaries from snapshot.spec.components,
              or empty list if no components found

    Raises:
        subprocess.CalledProcessError: If kubectl command fails
        json.JSONDecodeError: If snapshot data is invalid JSON
    """
    log(f"Retrieving components for snapshot {snapshot_name} in namespace {namespace}")

    snapshot_data = get_snapshot_data(namespace, snapshot_name, cmd_runner)

    if "spec" not in snapshot_data or "components" not in snapshot_data["spec"]:
        log(f"Error: No components found in snapshot {snapshot_name}")
        return []

    return snapshot_data["spec"]["components"]


def download_sbom_for_image(container_image: str, cmd_runner: Optional[ExternalCommands] = None) -> Optional[Dict[str, Any]]:
    """
    Download SBOM for a container image using cosign.

    Args:
        container_image: Full container image reference (e.g., registry/image:tag@sha256:...)
        cmd_runner: ExternalCommands instance for running cosign (defaults to new instance)

    Returns:
        dict: Parsed SBOM JSON data, or None if download/parsing fails

    Note:
        Errors are logged but not raised - returns None on failure to allow
        processing to continue for other components
    """
    if cmd_runner is None:
        cmd_runner = ExternalCommands()

    log(f"Downloading SBOM for image: {container_image}")

    try:
        output = cmd_runner.run_cosign(["download", "sbom", container_image])
        # Parse the SBOM JSON output
        sbom = json.loads(output)
        return sbom
    except subprocess.CalledProcessError as e:
        log(f"Failed to download SBOM for {container_image}: {e.stderr if e.stderr else e}")
        return None
    except json.JSONDecodeError as e:
        log(f"Failed to parse SBOM JSON for {container_image}: {e}")
        return None
    except Exception as e:
        log(f"Unknown error occurred while downloading SBOM for {container_image}: {e}")
        return None


def ensure_trivy_installed(cmd_runner: Optional[ExternalCommands] = None) -> bool:
    """
    Check if Trivy is installed, and install it if not found.

    Args:
        cmd_runner: ExternalCommands instance for checking trivy (defaults to new instance)

    Returns:
        bool: True if Trivy is available (already installed or successfully installed),
              False if installation failed

    Note:
        If Trivy is not found, this will automatically download and install it
        from GitHub releases with checksum verification
    """
    if cmd_runner is None:
        cmd_runner = ExternalCommands()

    is_available, version_output = cmd_runner.check_command_available("trivy")
    if is_available:
        log(f"Trivy is already installed: {version_output}")
        return True

    log("Trivy not found, installing...")
    install_trivy()

    # Verify installation
    is_available, version_output = cmd_runner.check_command_available("trivy")
    if is_available:
        log(f"Trivy installed successfully: {version_output}")
        return True
    else:
        log("ERROR: Failed to verify Trivy installation")
        return False


def ensure_diffused_lib_installed(cmd_runner: Optional[ExternalCommands] = None) -> bool:
    """
    Check if diffused-lib is installed, and install it if not found.

    Args:
        cmd_runner: ExternalCommands instance for running pip (defaults to new instance)

    Returns:
        bool: True if diffused-lib is available (already installed or successfully installed),
              False if installation failed

    Note:
        If diffused-lib is not found, this will automatically install version 0.2.0 using pip
    """
    try:
        import diffused.differ  # type: ignore[import-untyped]
        log("diffused-lib is already installed")
        return True
    except ImportError:
        log("diffused-lib not found, installing...")
        install_diffused_lib(cmd_runner)
        # Verify installation
        try:
            import diffused.differ  # type: ignore[import-untyped]
            log("diffused-lib installed successfully")
            return True
        except ImportError:
            log("ERROR: Failed to verify diffused-lib installation")
            return False


def compare_component_sboms(component_name: str, sbom_current: Dict[str, Any], sbom_previous: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compare two SBOMs for a specific component using diffused-lib.

    Uses Trivy to scan both SBOMs for vulnerabilities and then compares them
    to identify removed vulnerabilities between the previous and current release.

    Args:
        component_name: Name of the component being compared (for logging)
        sbom_current: Current SBOM data (dict/JSON structure)
        sbom_previous: Previous SBOM data (dict/JSON structure)

    Returns:
        dict: Comparison results with structure:
            {
                "vulnerabilities_removed": [...],  # Simple list of removed vulnerabilities
                "vulnerabilities_removed_details": [...]  # Detailed vulnerability info
            }

    Raises:
        Exception: If SBOM comparison fails (logged before raising)

    Note:
        Creates temporary files to store SBOMs, which are automatically cleaned up
    """
    from diffused.differ import VulnerabilityDiffer  # type: ignore[import-untyped]

    # Create a temporary directory to hold both SBOM files
    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            # Create temporary files for SBOMs
            current_path = os.path.join(tmpdir, 'current_sbom.json')
            previous_path = os.path.join(tmpdir, 'previous_sbom.json')

            with open(current_path, 'w') as f_current:
                json.dump(sbom_current, f_current)

            with open(previous_path, 'w') as f_previous:
                json.dump(sbom_previous, f_previous)

            # Use diffused-lib to compare SBOMs
            log(f"Comparing SBOMs for component {component_name} using diffused-lib")

            differ = VulnerabilityDiffer(
                previous_sbom=previous_path,
                next_sbom=current_path,
                scanner='trivy'
            )

            # Scan SBOMs for vulnerabilities
            differ.scan_sboms()

            # Get vulnerability differences
            differ.diff_vulnerabilities()

            # Return both the simple diff and detailed info
            diff_result = {
                "vulnerabilities_removed": differ.vulnerabilities_diff,
                "vulnerabilities_removed_details": differ.vulnerabilities_diff_all_info
            }

            return diff_result

        except Exception as e:
            log(f"Error comparing SBOMs for component {component_name}: {e}")
            raise
        # Temporary directory and files are automatically cleaned up here


def create_sbom_diff_record(component_diffs: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create a standardized JSON record for SBOM diff results.

    Args:
        component_diffs: Dictionary mapping component names to their diff results

    Returns:
        dict: Standardized output structure:
            {
                "releaseNotes": {
                    "sbomDiff": {
                        "component1": { diff_result },
                        "component2": { diff_result },
                        ...
                    }
                }
            }

    Example:
        >>> diffs = {
        ...     "my-app": {
        ...         "status": "compared",
        ...         "vulnerabilities_removed": ["CVE-2024-1234"],
        ...         "current_image": "registry/my-app:v2",
        ...         "previous_image": "registry/my-app:v1"
        ...     }
        ... }
        >>> create_sbom_diff_record(diffs)
        {'releaseNotes': {'sbomDiff': {'my-app': {...}}}}
    """
    result = {
        "releaseNotes": {
            "sbomDiff": component_diffs if component_diffs else {}
        }
    }
    return result


def compare_releases(cmd_runner: Optional[ExternalCommands] = None) -> Dict[str, Any]:
    """
    Main function to compare SBOMs between two releases.

    This function:
    1. Parses command-line arguments
    2. Validates input files exist
    3. Retrieves snapshot information from Kubernetes
    4. Downloads SBOMs for all components using cosign
    5. Compares SBOMs using Trivy and diffused-lib
    6. Returns structured results

    Args:
        cmd_runner: ExternalCommands instance for external command execution (defaults to new instance)

    Command-line Arguments:
        mode: Either 'tenant' or 'managed' (currently unused)
        --release, -r: Path to current release JSON file
        --previousRelease, -p: Path to previous release JSON file

    Returns:
        dict: Structured diff results in the format:
            {
                "releaseNotes": {
                    "sbomDiff": {
                        "component-name": {
                            "status": "compared|new|error",
                            "vulnerabilities_removed": [...],  # only if status=="compared"
                            "vulnerabilities_removed_details": [...],  # only if status=="compared"
                            "current_image": "...",
                            "previous_image": "...",  # only if status=="compared" or previous image exists
                            "reason": "..."  # only if status=="error"
                        }
                    }
                }
            }

    Raises:
        FileNotFoundError: If release files don't exist
        ValueError: If release files are invalid or missing required fields
        RuntimeError: If required dependencies cannot be installed
        subprocess.CalledProcessError: If kubectl or cosign commands fail

    Special Cases:
        - If previousRelease is empty, treats all components as new (first release)
        - All components are included in output, even if they fail processing
        - Components are marked with appropriate status:
            * "compared": Successfully compared with previous release
            * "new": Component didn't exist in previous release
            * "error": Failed to process (missing image, download failed, comparison failed)
        - Processing continues for all components even if some fail
    """
    if cmd_runner is None:
        cmd_runner = ExternalCommands()

    parser = argparse.ArgumentParser(description='Compare SBOMs between releases using diffused-lib')
    parser.add_argument(
        "mode",
        nargs='?',
        choices=["managed", "tenant"],
        help="Mode in which the script is called. It does not have any impact for this script."
    )
    parser.add_argument('-r', '--release', help='Path to current release file', required=True)
    parser.add_argument('-p', '--previousRelease', help='Path to previous release file', required=True)
    args = vars(parser.parse_args())

    # Validate input files exist
    if not os.path.isfile(args['release']):
        raise FileNotFoundError(f"Path to release file {args['release']} doesn't exist")
    if not os.path.isfile(args['previousRelease']):
        raise FileNotFoundError(f"Path to previousRelease file {args['previousRelease']} doesn't exist")

    # Read release files
    data_release = read_json(args['release'])
    data_prev_release = read_json(args['previousRelease'])

    if not data_release:
        raise ValueError(f"Empty release file {args['release']}")

    # Get snapshot information from current release
    snapshot_name = get_snapshot_name(data_release)
    snapshot_ns = get_snapshot_namespace(data_release)

    if not data_prev_release:
        log(f"INFO: Empty previous release file {args['previousRelease']} - this is the first release")
        # Get components from current release and mark them all as new
        current_components = get_components_from_snapshot(snapshot_ns, snapshot_name, cmd_runner)
        component_diffs = {}
        for current_comp in current_components:
            comp_name = current_comp['name']
            current_image = current_comp.get('containerImage')
            log(f"Component {comp_name} is new (first release)")

            # Validate containerImage
            validation_error = validate_container_image(current_image, comp_name, "current release")
            if validation_error:
                component_diffs[comp_name] = validation_error
            else:
                # After validation passes, current_image is guaranteed to be a non-empty string
                assert isinstance(current_image, str)
                component_diffs[comp_name] = {
                    "status": "new",
                    "current_image": current_image
                }
        return create_sbom_diff_record(component_diffs)

    snapshot_prev_name = get_snapshot_name(data_prev_release)
    snapshot_prev_ns = get_snapshot_namespace(data_prev_release)

    log(f"Current snapshot: {snapshot_name} (namespace: {snapshot_ns})")
    log(f"Previous snapshot: {snapshot_prev_name} (namespace: {snapshot_prev_ns})")

    # Verify both snapshots are in the same namespace for efficiency
    if snapshot_ns != snapshot_prev_ns:
        log(f"WARNING: Current and previous releases are in different namespaces ({snapshot_ns} vs {snapshot_prev_ns})")

    # Get components from both snapshots
    current_components = get_components_from_snapshot(snapshot_ns, snapshot_name, cmd_runner)
    previous_components = get_components_from_snapshot(snapshot_prev_ns, snapshot_prev_name, cmd_runner)

    if not current_components:
        raise ValueError("No components found in current release")

    # Create a map of component name to component data for previous release
    previous_components_map = {comp['name']: comp for comp in previous_components}

    log(f"Found {len(current_components)} components in current release")
    log(f"Found {len(previous_components)} components in previous release")

    # Ensure required dependencies are installed before processing components
    if not ensure_trivy_installed(cmd_runner):
        raise RuntimeError("Trivy installation failed")

    if not ensure_diffused_lib_installed(cmd_runner):
        raise RuntimeError("diffused-lib installation failed")

    # Compare SBOMs for each component
    component_diffs = {}

    for current_comp in current_components:
        comp_name = current_comp['name']
        current_image = current_comp.get('containerImage')

        # Validate current containerImage
        validation_error = validate_container_image(current_image, comp_name, "current release")
        if validation_error:
            component_diffs[comp_name] = validation_error
            continue

        # After validation passes, current_image is guaranteed to be a non-empty string
        assert isinstance(current_image, str)

        log(f"Processing component: {comp_name}")

        # Download SBOM for current component
        current_sbom = download_sbom_for_image(current_image, cmd_runner)
        if not current_sbom:
            log(f"WARNING: Could not download SBOM for current component {comp_name}")
            component_diffs[comp_name] = {
                "status": "error",
                "reason": "failed to download current SBOM",
                "current_image": current_image
            }
            continue

        # Check if component exists in previous release
        previous_comp = previous_components_map.get(comp_name)
        if previous_comp:
            previous_image = previous_comp.get('containerImage')

            # Validate previous containerImage
            validation_error = validate_container_image(previous_image, comp_name, "previous release")
            if validation_error:
                # Treat invalid previous image as a new component
                validation_error["status"] = "new"
                validation_error["current_image"] = current_image
                component_diffs[comp_name] = validation_error
                continue

            # After validation passes, previous_image is guaranteed to be a non-empty string
            assert isinstance(previous_image, str)

            # Download SBOM for previous component
            previous_sbom = download_sbom_for_image(previous_image, cmd_runner)
            if not previous_sbom:
                log(f"WARNING: Could not download SBOM for previous component {comp_name}")
                component_diffs[comp_name] = {
                    "status": "error",
                    "reason": "failed to download previous SBOM",
                    "current_image": current_image,
                    "previous_image": previous_image
                }
                continue

            # Compare the two SBOMs
            try:
                diff_result = compare_component_sboms(comp_name, current_sbom, previous_sbom)
                diff_result["status"] = "compared"
                diff_result["current_image"] = current_image
                diff_result["previous_image"] = previous_image
                component_diffs[comp_name] = diff_result
            except Exception as e:
                log(f"ERROR: Failed to compare SBOMs for component {comp_name}: {e}")
                component_diffs[comp_name] = {
                    "status": "error",
                    "reason": f"comparison failed: {str(e)}",
                    "current_image": current_image,
                    "previous_image": previous_image
                }
        else:
            # Component is new in this release
            log(f"Component {comp_name} is new in this release")
            component_diffs[comp_name] = {
                "status": "new",
                "current_image": current_image
            }

    return create_sbom_diff_record(component_diffs)


if __name__ == "__main__":
    try:
        result = compare_releases()
        print(json.dumps(result))
    except (ValueError, FileNotFoundError, RuntimeError) as e:
        log(f"ERROR: {e}")
        exit(1)
    except Exception as e:
        log(f"UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc(file=sys.stderr)
        exit(2)
