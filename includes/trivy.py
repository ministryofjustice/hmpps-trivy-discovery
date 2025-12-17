import requests
import tarfile
import logging
import subprocess
import os
import json
from time import sleep
from hmpps.services.job_log_handling import log_debug, log_info, log_warning, log_error
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


def scan_image(services, component, cache_dir, retry_count):
  component_name = component['component_name']
  component_build_image_tag = component['build_image_tag']
  image_name = f'{component["container_image_repo"]}:{component_build_image_tag}'
  image_id = ''
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
      ],
      capture_output=True,
      text=True,
      check=True,
    )
    scan_output = json.loads(result.stdout)
    result_json = scan_output.get('Results', [])
    image_id = scan_output.get('Metadata').get('ImageID')
    log_debug(f'Trivy scan result for {image_name} complete: {len(result_json)}')
    scan_summary = scan_result_summary(result_json)

    trivy_scans.update(
      services, component_name, component_build_image_tag, image_id, scan_summary
    )
  except subprocess.CalledProcessError as e:
    if 'DB error' in e.stderr and retry_count <= 3:
      retry_count += 1
      log_info(f'Retrying Trivy scan for {image_name} - attempt {retry_count}...')
      sleep(5)
      scan_image(services, component, cache_dir, retry_count)
    else:
      # only needs to be a warning if the image can't be found
      if 'unable to find the specified image' in e.stderr:
        log_warning(f'Trivy scan failed for {image_name}: {e.stderr}')
        scan_status = 'Failed (image not found)'
      else:
        log_error(f'Trivy scan failed for {image_name}: {e.stderr}')
        scan_status = 'Failed (encountered an error - check logs)'
      scan_summary = {}
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


def scan_prod_image(services, components, max_threads):
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
        f'images ({int(count / qty * 100)}%)'
      )
      scan_image(services, component, cache_dir, 1)
    count += 1
  log_info('Completed all Trivy scans.')
