import subprocess
import urllib.request
import tarfile
import threading
import sys
import logging
import os
import json
import re
from time import sleep
from utilities.discovery import job
import processes.scheduled_jobs as sc_scheduled_job
import processes.trivy_scans as trivy_scans

log = logging.getLogger(__name__)
cache_dir = '/app/trivy_cache' if os.path.exists('/app/trivy_cache') else '/tmp'

def install(services):
  try:
    # Get the latest Trivy version
    trivy_version = subprocess.check_output(
      'wget -qO- https://api.github.com/repos/aquasecurity/trivy/releases/latest | jq -r .tag_name',
      shell=True,
      text=True,
    ).strip()
    log.info(f'Trivy version: {trivy_version}')
    trivy_version_stripped = trivy_version.lstrip('v')
    # Define the URL for the Trivy binary
    trivy_url = f'https://github.com/aquasecurity/trivy/releases/download/{trivy_version}/trivy_{trivy_version_stripped}_Linux-64bit.tar.gz'
    trivy_tar = f'trivy_{trivy_version_stripped}_Linux-64bit.tar.gz'

    # Download the Trivy binary
    log.info(f'Downloading Trivy from {trivy_url}...')
    urllib.request.urlretrieve(trivy_url, trivy_tar)

    # Extract the tar.gz file
    log.info('Extracting Trivy...')
    with tarfile.open(trivy_tar, 'r:gz') as tar:
      tar.extractall()
    log.info('Trivy installed successfully.')

  except subprocess.CalledProcessError as e:
    log.error(f'Failed to install Trivy: {e}', file=sys.stderr)
    job.error_messages.append(f'Failed to install Trivy: {e}')
    sc_scheduled_job.update(services, 'Failed')
    job.services.slack.alert(f'hmpps-trivy-discovery: failed to install Trivy - {e}')
    raise SystemExit(e) from e

def scan_image(services, component, cache_dir):
  component_name = component['component_name']
  component_build_image_tag = component['build_image_tag']
  image_name = f'{component["container_image_repo"]}:{component_build_image_tag}'
  log.info(f'Running Trivy scan on {image_name}')

  try:
    result = subprocess.run(
      [
        'trivy',
        'image',
        image_name,
        '--severity',
        'HIGH,CRITICAL',
        '--format',
        'json',
        '--ignore-unfixed',
        '--skip-dirs',
        '/usr/local/lib/node_modules/npm',
        '--skip-files',
        '/app/agent.jar',
        '--cache-dir',
        cache_dir,
      ],
      capture_output=True,
      text=True,
      check=True,
    )
    scan_output = json.loads(result.stdout)
    results_section = scan_output.get('Results', [])
    # Check if there are any vulnerabilities
    has_vulnerabilities = any(
      result.get('Vulnerabilities') for result in results_section
    )

    # Display the appropriate message
    result_json =[]
    if has_vulnerabilities:
      result_json = results_section
    else:
      result_json.append({'message': 'No vulnerabilities in container image'})

    log.info(f'Trivy scan result for {image_name}:\n{result_json}')
    trivy_scans.update(services, component_name, component_build_image_tag, result_json)
  except subprocess.CalledProcessError as e:
    log.error(f'Trivy scan failed for {image_name}: {e.stderr}')
    fatal_error_match = re.search(r"FATAL\s+(.*)", e.stderr)
    result_json = []
    if fatal_error_match:
      fatal_error_message = fatal_error_match.group(1)
      result_json.append({"error": fatal_error_message})
    else:
      result_json.append({"error": e.stderr})
    trivy_scan_results.upload(component_name, component_build_image_tag, result_json, 'Failed')

def scan_prod_image(services, components, max_threads):
  sc = services.sc
  log.info(f'Starting scan for {len(components)} components...')
  threads = []

  for component in components:
    if not isinstance(component, dict):
      log.error(f'Invalid component format: {component}')
      continue

    if 'build_image_tag' in component and component['build_image_tag']:
      t = threading.Thread(target=scan_image, args=(services, component, cache_dir))
      threads.append(t)

      # Start the thread
      t.start()
      log.info(f'Started thread for {component["component_name"]}')

      # Limit the number of active threads to max_threads
      while threading.active_count() > max_threads:
        log.debug(
          f'Active Threads={threading.active_count()}, Max Threads={max_threads}'
        )
        sleep(1)

  # Wait for all threads to complete
  for t in threads:
    t.join()

  log.info('Completed all Trivy scans.')