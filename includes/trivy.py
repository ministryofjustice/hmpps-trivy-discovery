import requests
import tarfile
import logging
import subprocess
import os
import json
import re
from time import sleep
from hmpps.services.job_log_handling import (
  log_debug,
  log_error,
  log_info,
)
import processes.trivy_scans as trivy_scans

log = logging.getLogger(__name__)
cache_dir = '/app/trivy_cache' if os.path.exists('/app/trivy_cache') else '/tmp'


def install():
  try:
    # Get the latest Trivy version

    response = requests.get(
      'https://api.github.com/repos/aquasecurity/trivy/releases/latest'
    )
    if trivy_version := response.json().get('tag_name'):
      log_info(f'Trivy version: {trivy_version}')
    else:
      return 'Failed to install Trivy - unable to retrieve version'

    trivy_version_stripped = trivy_version.lstrip('v')
    # Define the URL for the Trivy binary
    trivy_url = (
      f'https://github.com/aquasecurity/trivy/releases/download/'
      f'{trivy_version}/trivy_{trivy_version_stripped}_Linux-64bit.tar.gz'
    )
    trivy_tar = f'trivy_{trivy_version_stripped}_Linux-64bit.tar.gz'

    # Download the Trivy binary
    log_info(f'Downloading Trivy from {trivy_url}...')
    response = requests.get(trivy_url, stream=True)
    response.raise_for_status()  # Optional: raises an error for bad responses

    with open(trivy_tar, 'wb') as f:
      for chunk in response.iter_content(chunk_size=8192):
        f.write(chunk)
    f.close()

    # Extract the tar.gz file
    log_info('Extracting Trivy...')
    with tarfile.open(trivy_tar, 'r:gz') as tar:
      tar.extractall()
    log_info('Trivy installed successfully.')

  except Exception as e:  # Not a CalledProcess error - it could happen
    return f'Failed to install Trivy - {e}'

  try:
    subprocess.run(
      ['trivy', 'image', '--download-db-only'],
      capture_output=True,
      text=True,
      check=True,
    )
    log_info('Trivy DB downloaded successfully.')
  except subprocess.CalledProcessError as e:
    return f'Failed to download Trivy DB - {e.stderr}'
  return 'Success'

def run_trivy_scan(image_name, retry_count=0):
    global cache_dir
    log_info(f'Running Trivy scan on {image_name}')
    try:
        result = subprocess.run(
            [
                'trivy',
                'image',
                image_name,
                '--format',
                'json',
                '--skip-dirs',
                '/usr/local/lib/node_modules/npm',
                '--skip-files',
                '/app/agent.jar',
                '--scanners',
                'vuln,secret,misconfig',
                '--image-config-scanners',
                'misconfig,secret',
                '--cache-dir',
                cache_dir,
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        scan_output = json.loads(result.stdout)
        image_id = scan_output.get('Metadata', {}).get('ImageID', '')
        result_json = scan_output.get('Results', [])
        log_debug(f'Trivy scan result for {image_name} complete: {len(result_json)}')
        return result_json, image_id
    except subprocess.CalledProcessError as e:
        if 'DB error' in e.stderr and retry_count < 3:
            retry_count += 1
            log_info(f'Retrying Trivy scan for {image_name} - attempt {retry_count}...')
            sleep(5)
            return run_trivy_scan(image_name, retry_count)
        else:
            log_error(f'Trivy scan failed for {image_name}: {e.stderr}')
            if 'Fatal error' in e.stderr:
                fatal_error_match = re.search(r'FATAL\s+(.*)', e.stderr)
                fatal_error_message = fatal_error_match.group(1) if fatal_error_match else 'Unknown fatal error'
                return [{'error': fatal_error_message}], ''
            else:
                return [{'error': e.stderr}], ''
            
def scan_component_image(services, component, retry_count):
    """
    Scan an image associated with a component and update the scan results.
    """
    component_name = component['component_name']
    component_build_image_tag = component['build_image_tag']
    image_name = f'{component["container_image_repo"]}:{component_build_image_tag}'

    # Perform the Trivy scan
    result_json, image_id = run_trivy_scan(image_name, retry_count)

    # Summarize the scan results
    scan_summary = scan_result_summary(result_json) if result_json else {}
    scan_status = 'Failed' if not result_json else 'Succeeded'

    # Update the scan results
    trivy_scans.update(
        services,
        component_name,
        component_build_image_tag,
        image_id,
        scan_summary,
        scan_status,
    )


def scan_result_summary(scan_result):
  scan_summary = {
    'scan_result': {},
    'summary': {
      'os-pkgs': {'fixed': {}, 'unfixed': {}},
      'lang-pkgs': {'fixed': {}, 'unfixed': {}},
      'secret': {},
    },
  }

  def increment_summary(summary_section, severity, fixed=False):
    key = 'fixed' if fixed else 'unfixed'
    if key not in summary_section:
      summary_section[key] = {}
    summary_section[key][severity] = summary_section[key].get(severity, 0) + 1

  for result in scan_result:
    if not isinstance(result, dict):
      raise ValueError(
        f'Unexpected data type for result: {type(result)}. Expected a dictionary.'
      )

    vulnerabilities = result.get('Vulnerabilities', [])
    secrets = result.get('Secrets', [])

    # Process vulnerabilities (os-pkgs and lang-pkgs)
    if vulnerabilities:
      for vuln in vulnerabilities:
        class_type = result.get('Class')
        severity = vuln.get('Severity', 'UNKNOWN')
        description = (
          f'{vuln.get("Description", "")}'
          if severity in ('CRITICAL', 'HIGH')
          else f'{vuln.get("Description", "")[:40]}...'
        )
        scan_summary['scan_result'].setdefault(class_type, []).append(
          {
            'PkgName': vuln.get('PkgName', 'N/A'),
            'Severity': severity,
            'Title': vuln.get('Title', ''),
            'Description': description,
            'InstalledVersion': vuln.get('InstalledVersion', 'N/A'),
            'FixedVersion': vuln.get('FixedVersion', 'N/A'),
            'VulnerabilityID': vuln.get('VulnerabilityID', 'N/A'),
            'PrimaryURL': vuln.get('PrimaryURL', 'N/A'),
          }
        )
        increment_summary(
          scan_summary['summary'][class_type],
          vuln.get('Severity', 'UNKNOWN'),
          fixed=bool(vuln.get('FixedVersion')),
        )

    # Process secrets (secret)
    if secrets:
      for secret in secrets:
        scan_summary['scan_result'].setdefault('secret', []).append(
          {
            'Severity': secret.get('Severity', 'UNKNOWN'),
            'Description': secret.get('Title', 'N/A'),
            'FilePath': result.get('Target', 'N/A'),
            'LineNumber': secret.get('StartLine', 'N/A'),
            'AdditionalContext': secret.get('Match', 'N/A'),
          }
        )
        severity = secret.get('Severity', 'UNKNOWN')
        scan_summary['summary']['secret'][severity] = (
          scan_summary['summary']['secret'].get(severity, 0) + 1
        )
  return scan_summary


def scan_prod_image(services, components):
  qty = len(components)
  log_info(f'Starting scan for {qty} images...')
  count = 1
  for component in components:
    if not isinstance(component, dict):
      log_error(f'Invalid component format: {component}')
      continue

    if 'build_image_tag' in component and component['build_image_tag']:
      log_info(
        f'Started Trivy scan for {component["component_name"]} - {count}/{qty} '
        f'images ({int(count / qty) * 100}%)'
      )
      scan_component_image(services, component, 1)
    count += 1
  log_info('Completed all Trivy scans.')

def scan_hmpps_base_container_images(services):
  log_info('Starting scan for hmpps-basec-container-images...')
  images = ['hmpps-python', 'hmpps-node', 'hmpps-eclipse-temurin']
  for image in images:
    log_info(f'Started Trivy scan for {image}')
    image_name = f'ghcr.io/ministryofjustice/{image}:latest'
    # Perform the Trivy scan
    result_json, image_id = run_trivy_scan(image_name, 1)

    # Summarize the scan results
    scan_summary = scan_result_summary(result_json) if result_json else {}
    scan_status = 'Failed' if not result_json else 'Succeeded'

    # Update the scan results
    trivy_scans.update(
        services,
        f'hmpps-base-container-images:{image}',
        'latest',
        image_id,
        scan_summary,
        scan_status,
    )
