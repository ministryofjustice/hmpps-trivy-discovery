#!/usr/bin/env python
import os
import sys
import json
import logging
import threading
import logging
import subprocess
import urllib.request
import tarfile
from time import sleep
from datetime import datetime
from classes.service_catalogue import ServiceCatalogue
from classes.slack import Slack


SC_API_ENDPOINT = os.getenv('SERVICE_CATALOGUE_API_ENDPOINT')
SC_API_TOKEN = os.getenv('SERVICE_CATALOGUE_API_KEY')
SC_FILTER = os.getenv('SC_FILTER', '')
SC_SORT = ''
SC_API_ENVIRONMENTS_ENDPOINT = 'environments?populate=component'
SC_API_TRIVY_SCANS_ENDPOINT = 'trivy-scans?populate=*'
SLACK_ALERT_CHANNEL = os.getenv('SLACK_ALERT_CHANNEL', '')
SLACK_BOT_TOKEN = os.getenv('SLACK_BOT_TOKEN', '')

# Set maximum number of concurrent threads to run, try to avoid secondary github api limits.
MAX_THREADS = 5
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO').upper()


def install_trivy(slack):
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

  except subprocess.CalledProcessError as e:
    log.error(f'Failed to install Trivy: {e}', file=sys.stderr)
    slack.alert(f'hmpps-trivy-discovery: failed to install Trivy - {e}')
    raise SystemExit(e) from e


def delete_sc_trivy_scan_results(sc):
  # Fetch the list of records
  trivy_data = sc.get_all_records(SC_API_TRIVY_SCANS_ENDPOINT)
  for record in trivy_data:
    record_id = record['id']
    sc.delete('trivy-scans', record_id)


def upload_sc_trivy_scan_results(component, image_tag, result, sc):
  trivy_scan_data = {
    'name': component,
    'trivy_scan_results': result,
    'build_image_tag': image_tag,
    'trivy_scan_timestamp': datetime.now().isoformat(),
  }
  if response := sc.add(SC_API_TRIVY_SCANS_ENDPOINT, trivy_scan_data):
    trivy_scan_id = response.get('data', {}).get('id', {})
    if trivy_scan_id:
      # rather unpleasant workaround with the label field since it's underneath component
      if environments := sc.get_record_list(
        SC_API_ENVIRONMENTS_ENDPOINT, 'component][name', component
      ):
        for environment in environments:
          log.debug(f'environment: {environment}')
          environment_id = environment['id']
          sc.update('environments', environment_id, {'trivy_scan': trivy_scan_id})
          log.info(
            f'Updated environment {environment_id} with Trivy scan ID: {trivy_scan_id}'
          )
      else:
        log.warning(f'No environments found for {component}')
    else:
      log.warning(f'No trivy_scan_id found for {component}')


def extract_image_list(environments_data):
  filtered_components = []
  unique_components = set()

  for environment in environments_data:
    if component := environment.get('attributes', {}).get('component', {}):
      component_data = component.get('data', {})
      component_attributes = (
        component_data.get('attributes', {}) if component_data else {}
      )
      component_name = component_attributes.get('name')
      if build_image_tag := environment.get('attributes', {}).get('build_image_tag'):
        log.debug(
          f'environment build image tag for {component_attributes.get("name")}: {environment.get("attributes").get("build_image_tag")}'
        )
        container_image_repo = component_attributes.get('container_image')
        filtered_component = {
          'component_name': component_name,
          'container_image_repo': container_image_repo,
          'build_image_tag': build_image_tag,
        }
        log.debug(f'filtered_component: {filtered_component}')
        # Convert the dictionary to a tuple of items to make it hashable
        component_tuple = tuple(filtered_component.items())
        if component_tuple not in unique_components:
          unique_components.add(component_tuple)
          filtered_components.append(filtered_component)
      else:
        log.warning(
          f'No build image tag for {environment.get("attributes").get("name")} in {component_name}'
        )

  log.info(f'Number of environments records in SC: {len(environments_data)}')
  log.info(f'Number of images: {len(filtered_components)}')
  return filtered_components


def run_trivy_scan(component, cache_dir, sc):
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
    if has_vulnerabilities:
      result_json = results_section
    else:
      result_json = {'message': 'No vulnerabilities in container image'}

    log.info(f'Trivy scan result for {image_name}:\n{result_json}')
    upload_sc_trivy_scan_results(
      component_name, component_build_image_tag, result_json, sc
    )
  except subprocess.CalledProcessError as e:
    log.error(f'Trivy scan failed for {image_name}: {e.stderr}')


def scan_prod_image(components, cache_dir, sc):
  log.info(f'Starting scan for {len(components)} components...')
  threads = []

  for component in components:
    if not isinstance(component, dict):
      log.error(f'Invalid component format: {component}')
      continue

    if 'build_image_tag' in component and component['build_image_tag']:
      t = threading.Thread(target=run_trivy_scan, args=(component, cache_dir, sc))
      threads.append(t)

      # Start the thread
      t.start()
      log.info(f'Started thread for {component["component_name"]}')

      # Limit the number of active threads to MAX_THREADS
      while threading.active_count() > MAX_THREADS:
        log.debug(
          f'Active Threads={threading.active_count()}, Max Threads={MAX_THREADS}'
        )
        sleep(1)

  # Wait for all threads to complete
  for t in threads:
    t.join()

  log.info('Completed all Trivy scans.')


def get_new_container_image_list(image_list, sc):
  new_image_list = []
  trivy_data = sc.get_all_records(SC_API_TRIVY_SCANS_ENDPOINT)
  for image in image_list:
    build_image_tag = image['build_image_tag']
    if not any(
      trivy['attributes']['build_image_tag'] == build_image_tag for trivy in trivy_data
    ):
      new_image_list.append(image)
  log.info(f'Number of new images to scan: {len(new_image_list)}')
  return new_image_list


################# Main functions #################

if __name__ == '__main__':
  logging.basicConfig(
    format='[%(asctime)s] %(levelname)s %(threadName)s %(message)s', level=LOG_LEVEL
  )
  log = logging.getLogger(__name__)
  if '-f' in os.sys.argv or '--full' in os.sys.argv:
    log.info('Running Trivy scan on all container images in Service Catalogue')
    log.info('********************************************************************')
    incremental_scan = False
  elif '-i' in os.sys.argv or '--incremental' in os.sys.argv:
    log.info('Running Trivy scan on new images only')
    log.info('********************************************************************')
    incremental_scan = True
  else:
    log.error(
      'Invalid argument. Use -i or --incremental for incremental scan or -f or --full for full scan'
    )
    sys.exit(1)

  sc = ServiceCatalogue(
    {
      'url': SC_API_ENDPOINT,
      'key': SC_API_TOKEN,
      'filter': SC_FILTER,
    },
    LOG_LEVEL,
  )

  slack = Slack(
    {'token': SLACK_BOT_TOKEN, 'alert_channel': SLACK_ALERT_CHANNEL}, LOG_LEVEL
  )

  if not sc.connection_ok:
    log.error('Failed to connect to the Service Catalogue. Exiting...')
    slack.alert('hmpps-trivy-discovery: failed to connect to the Service Catalogue')
    sys.exit(1)

  # Install Trivy
  install_trivy(slack)

  # Fetch components data from Service Catalogue
  environments_data = sc.get_all_records(SC_API_ENVIRONMENTS_ENDPOINT)

  # Extract im                                          age list data from environments data
  image_list = extract_image_list(environments_data)
  if incremental_scan:
    image_list = get_new_container_image_list(image_list, sc)
  else:
    delete_sc_trivy_scan_results(sc)

  cache_dir = '/app/trivy_cache' if os.path.exists('/app/trivy_cache') else '/tmp'
  scan_prod_image(image_list, cache_dir, sc)
