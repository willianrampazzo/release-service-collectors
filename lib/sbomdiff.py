#!/usr/bin/env python
"""
python lib/sbom_diff.py \
    tenant \
    --release release.json \
    --previousRelease previous_release.json
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile


def log(message):
    print(message, file=sys.stderr)


def read_json(file):
    if os.path.getsize(file) > 0:
        with open(file, 'r') as f:
            data = json.load(f)
        return data


def get_snapshot_name(data_release):
    if "spec" in data_release:
        spec = data_release["spec"]
        if "snapshot" in spec:
            return spec["snapshot"]
        else:
            log(f"Error: missing 'snapshot' key in {spec}")
            exit(1)
    else:
        log(f"Error: missing 'spec' key in {data_release}")
        exit(1)


def get_snapshot_namespace(data_release):
    if "metadata" in data_release:
        metadata = data_release["metadata"]
        if "namespace" in metadata:
            return metadata["namespace"]
        else:
            log(f"Error: missing 'namespace' key in {metadata}")
            exit(1)
    else:
        log(f"Error: missing 'metadata' key in {data_release}")
        exit(1)


def get_snapshot_data(namespace, snapshot):
    cmd = ["kubectl", "get", "snapshot", snapshot, "-n", namespace, "-ojson"]
    cmd_str = " ".join(cmd)
    try:
        log(f"Running {cmd_str}")
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError:
        log(f"Command {cmd_str} failed, check exception for details")
        raise
    except Exception as exc:
        log("Unknown error occurred")
        raise RuntimeError from exc

    log(result.stdout)
    return json.loads(result.stdout)


def install_trivy():
    """Install Trivy binary from GitHub releases"""
    import platform
    import urllib.request
    import tarfile
    import shutil

    log("Installing Trivy...")

    # Determine the system architecture and OS
    system = platform.system().lower()
    machine = platform.machine().lower()

    # Map machine architecture to Trivy's naming convention
    if machine == "x86_64" or machine == "amd64":
        arch = "64bit"
    elif machine == "aarch64" or machine == "arm64":
        arch = "ARM64"
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

    # Get the latest version
    trivy_version = "0.58.1"  # You can update this or fetch latest from API
    filename = f"trivy_{trivy_version}_{os_name}-{arch}.tar.gz"
    url = f"https://github.com/aquasecurity/trivy/releases/download/v{trivy_version}/{filename}"

    log(f"Downloading Trivy from {url}")

    try:
        # Create a temporary directory for download
        with tempfile.TemporaryDirectory() as tmpdir:
            archive_path = os.path.join(tmpdir, filename)

            # Download the archive
            urllib.request.urlretrieve(url, archive_path)
            log(f"Downloaded Trivy archive to {archive_path}")

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


def install_diffused_lib():
    """Install diffused-lib package using pip"""
    log("Installing diffused-lib package...")
    cmd = [sys.executable, "-m", "pip", "install", "diffused-lib"]
    try:
        cmd_str = " ".join(cmd)
        log(f"Running {cmd_str}")
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        log(result.stdout)
    except subprocess.CalledProcessError as e:
        log(f"Failed to install diffused-lib: {e.stderr}")
        raise
    except Exception as exc:
        log("Unknown error occurred during package installation")
        raise RuntimeError from exc


def get_components_from_snapshot(namespace, snapshot_name):
    """Get components list from snapshot"""
    log(f"Retrieving components for snapshot {snapshot_name} in namespace {namespace}")

    snapshot_data = get_snapshot_data(namespace, snapshot_name)

    if "spec" not in snapshot_data or "components" not in snapshot_data["spec"]:
        log(f"Error: No components found in snapshot {snapshot_name}")
        return []

    return snapshot_data["spec"]["components"]


def download_sbom_for_image(container_image):
    """Download SBOM for a container image using cosign"""
    log(f"Downloading SBOM for image: {container_image}")

    cmd = ["cosign", "download", "sbom", container_image]
    try:
        cmd_str = " ".join(cmd)
        log(f"Running {cmd_str}")
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)

        # Parse the SBOM JSON output
        sbom = json.loads(result.stdout)
        return sbom
    except subprocess.CalledProcessError as e:
        log(f"Failed to download SBOM for {container_image}: {e.stderr}")
        return None
    except json.JSONDecodeError as e:
        log(f"Failed to parse SBOM JSON for {container_image}: {e}")
        return None
    except Exception as exc:
        log(f"Unknown error occurred while downloading SBOM for {container_image}")
        return None


def ensure_trivy_installed():
    """Check if Trivy is installed, install if not"""
    try:
        result = subprocess.run(["trivy", "--version"], capture_output=True, text=True, check=True)
        log(f"Trivy is already installed: {result.stdout.strip()}")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        log("Trivy not found, installing...")
        install_trivy()
        # Verify installation
        try:
            result = subprocess.run(["trivy", "--version"], capture_output=True, text=True, check=True)
            log(f"Trivy installed successfully: {result.stdout.strip()}")
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            log("ERROR: Failed to verify Trivy installation")
            return False


def compare_component_sboms(component_name, sbom_current, sbom_previous):
    """Compare two SBOMs for a specific component using diffused-lib"""
    # Ensure Trivy is installed before proceeding
    if not ensure_trivy_installed():
        raise RuntimeError("Trivy installation failed")

    try:
        from diffused.differ import VulnerabilityDiffer

        # Create temporary files for SBOMs
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f_current:
            json.dump(sbom_current, f_current)
            current_path = f_current.name

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f_previous:
            json.dump(sbom_previous, f_previous)
            previous_path = f_previous.name

        try:
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
        finally:
            # Clean up temporary files
            os.unlink(current_path)
            os.unlink(previous_path)

    except ImportError:
        log("diffused-lib not found, attempting to install...")
        install_diffused_lib()
        # Retry import after installation
        from diffused.differ import VulnerabilityDiffer
        return compare_component_sboms(component_name, sbom_current, sbom_previous)


def create_sbom_diff_record(component_diffs):
    """
    Create a standardized JSON record for SBOM diff results
    Input: component_diffs (dict) - mapping of component names to their diff results
    Output format:
    {
        "releaseNotes": {
            "sbomDiff": {
                "component1": { diff_result },
                "component2": { diff_result }
            }
        }
    }
    """
    result = {
        "releaseNotes": {
            "sbomDiff": component_diffs if component_diffs else {}
        }
    }
    return result


def compare_releases():
    parser = argparse.ArgumentParser(description='Compare SBOMs between releases using diffused-lib')
    parser.add_argument(
        "mode",
        choices=["managed", "tenant"],
        help="Mode in which the script is called. It does not have any impact for this script."
    )
    parser.add_argument('-r', '--release', help='Path to current release file', required=True)
    parser.add_argument('-p', '--previousRelease', help='Path to previous release file', required=True)
    args = vars(parser.parse_args())

    # Validate input files exist
    file_not_exists = 0
    if not os.path.isfile(args['release']):
        log(f"ERROR: Path to release file {args['release']} doesn't exist")
        file_not_exists = 1
    if not os.path.isfile(args['previousRelease']):
        log(f"ERROR: Path to previousRelease file {args['previousRelease']} doesn't exist")
        file_not_exists = 1
    if file_not_exists:
        exit(1)

    # Read release files
    data_release = read_json(args['release'])
    data_prev_release = read_json(args['previousRelease'])

    if not data_release:
        log(f"ERROR: Empty release file {args['release']}")
        exit(1)

    # Get snapshot information from current release
    snapshot_name = get_snapshot_name(data_release)
    snapshot_ns = get_snapshot_namespace(data_release)

    if not data_prev_release:
        log(f"INFO: Empty previous release file {args['previousRelease']} - this is the first release")
        # Get components from current release and set them all as empty dicts
        current_components = get_components_from_snapshot(snapshot_ns, snapshot_name)
        component_diffs = {}
        for current_comp in current_components:
            comp_name = current_comp['name']
            log(f"Component {comp_name} is new (first release)")
            component_diffs[comp_name] = {}
        return create_sbom_diff_record(component_diffs)

    snapshot_prev_name = get_snapshot_name(data_prev_release)

    log(f"Current snapshot: {snapshot_name}")
    log(f"Previous snapshot: {snapshot_prev_name}")

    # Get components from both snapshots
    current_components = get_components_from_snapshot(snapshot_ns, snapshot_name)
    previous_components = get_components_from_snapshot(snapshot_ns, snapshot_prev_name)

    if not current_components:
        log("ERROR: No components found in current release")
        exit(1)

    # Create a map of component name to component data for previous release
    previous_components_map = {comp['name']: comp for comp in previous_components}

    log(f"Found {len(current_components)} components in current release")
    log(f"Found {len(previous_components)} components in previous release")

    # Compare SBOMs for each component
    component_diffs = {}

    for current_comp in current_components:
        comp_name = current_comp['name']
        current_image = current_comp.get('containerImage')

        if not current_image:
            log(f"WARNING: No containerImage found for component {comp_name}")
            continue

        log(f"Processing component: {comp_name}")

        # Download SBOM for current component
        current_sbom = download_sbom_for_image(current_image)
        if not current_sbom:
            log(f"WARNING: Could not download SBOM for current component {comp_name}")
            continue

        # Check if component exists in previous release
        if comp_name in previous_components_map:
            previous_comp = previous_components_map[comp_name]
            previous_image = previous_comp.get('containerImage')

            if not previous_image:
                log(f"WARNING: No containerImage found for previous component {comp_name}")
                component_diffs[comp_name] = {"status": "new", "reason": "no previous image"}
                continue

            # Download SBOM for previous component
            previous_sbom = download_sbom_for_image(previous_image)
            if not previous_sbom:
                log(f"WARNING: Could not download SBOM for previous component {comp_name}")
                component_diffs[comp_name] = {"status": "error", "reason": "failed to download previous SBOM"}
                continue

            # Compare the two SBOMs
            diff_result = compare_component_sboms(comp_name, current_sbom, previous_sbom)
            component_diffs[comp_name] = diff_result
        else:
            # Component is new in this release
            log(f"Component {comp_name} is new in this release")
            component_diffs[comp_name] = {"status": "new"}

    return create_sbom_diff_record(component_diffs)


if __name__ == "__main__":
    result = compare_releases()
    print(json.dumps(result))
