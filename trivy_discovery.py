#!/usr/bin/env python
import os
import sys
import requests
import json
import logging
import threading
import logging
import subprocess
import urllib.request
import tarfile
from time import sleep
from datetime import datetime

SC_API_ENDPOINT = os.getenv('SERVICE_CATALOGUE_API_ENDPOINT')
SC_API_TOKEN = os.getenv('SERVICE_CATALOGUE_API_KEY')
SC_FILTER = os.getenv('SC_FILTER', '')
SC_PAGE_SIZE = 10
SC_PAGINATION_PAGE_SIZE = f'&pagination[pageSize]={SC_PAGE_SIZE}'
SC_SORT = ''
SC_API_ENVIRONMENTS_ENDPOINT = f'{SC_API_ENDPOINT}/v1/environments?populate=component&{SC_FILTER}'
SC_API_TRIVY_SCANS_ENDPOINT = f'{SC_API_ENDPOINT}/v1/trivy-scans'
# Set maximum number of concurrent threads to run, try to avoid secondary github api limits.
MAX_THREADS = 5
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO').upper()

def install_trivy():
  try:
    # Get the latest Trivy version
    trivy_version = subprocess.check_output(
      "wget -qO- https://api.github.com/repos/aquasecurity/trivy/releases/latest | jq -r .tag_name",
        shell=True,
        text=True
    ).strip()
    log.info(f"Trivy version: {trivy_version}")
    trivy_version_stripped = trivy_version.lstrip('v')
    # Define the URL for the Trivy binary
    trivy_url = f"https://github.com/aquasecurity/trivy/releases/download/{trivy_version}/trivy_{trivy_version_stripped}_Linux-64bit.tar.gz"
    trivy_tar = f"trivy_{trivy_version_stripped}_Linux-64bit.tar.gz"

    # Download the Trivy binary
    log.info(f"Downloading Trivy from {trivy_url}...")
    urllib.request.urlretrieve(trivy_url, trivy_tar)

    # Extract the tar.gz file
    log.info("Extracting Trivy...")
    with tarfile.open(trivy_tar, "r:gz") as tar:
      tar.extractall()

  except subprocess.CalledProcessError as e:
    log.error(f"Failed to install Trivy: {e}", file=sys.stderr)
    raise SystemExit(e) from e
  
def fetch_sc_data(API_ENDPOINT):
  sc_result_data = []  
  try:
    r = requests.get(API_ENDPOINT, headers=sc_api_headers, timeout=10)
  except Exception as e:
    log.error(f"Error getting environments from SC: {e}")
    return None

  if r.status_code == 200:
    j_meta = r.json()["meta"]["pagination"]
    log.debug(f"Got result page: {j_meta['page']} from SC")
    sc_result_data.extend(r.json()["data"])
  else:
    raise Exception(f"Received non-200 response from Service Catalogue: {r.status_code}")
    return None

  # Loop over the remaining pages and collect all data
  num_pages = j_meta['pageCount']
  for p in range(2, num_pages + 1):
    page = f"&pagination[page]={p}"
    r = requests.get(f"{API_ENDPOINT}{page}", headers=sc_api_headers, timeout=10)
    if r.status_code == 200:
      log.debug(f"Got result page: {p} from SC")
      sc_result_data.extend(r.json()["data"])
    else:
      raise Exception(f"Received non-200 response from Service Catalogue: {r.status_code}")
      return None
  return sc_result_data

def delete_sc_trivy_scan_results():
  try:
    # Fetch the list of records
    trivy_data = fetch_sc_data(SC_API_TRIVY_SCANS_ENDPOINT)
    for record in trivy_data:
      record_id = record['id']
      delete_response = requests.delete(f"{SC_API_TRIVY_SCANS_ENDPOINT}/{record_id}", headers=sc_api_headers, timeout=10)
      if delete_response.status_code == 200:
        log.info(f"Deleted Trivy scan result with ID: {record_id}")
      else:
        log.error(f"Failed to delete Trivy scan result with ID: {record_id} - Status code: {delete_response.status_code}")
  except Exception as e:
    log.error(f"Error deleting previous Trivy scan results: {e}")

def upload_sc_trivy_scan_results(component, image_tag, result):
  trivy_scan_data = {
    'name': component,
    'trivy_scan_results': result,
    'build_image_tag': image_tag,
    'trivy_scan_timestamp': datetime.now().isoformat()
  }
  try:
    r = requests.post(
        f'{SC_API_TRIVY_SCANS_ENDPOINT}',
          headers=sc_api_headers,
          json={'data': trivy_scan_data},
          timeout=10,
        )
    if r.status_code == 200:
      log.info(f"Inserted Trivy scan result for {image_tag}")
    else:
      log.error(f"Failed to insert Trivy scan result for {image_tag}: {r.status_code}")
  except Exception as e:
    log.error(f"Error updating Trivy scan result for {component}{image_tag}: {e}")
  trivy_scan_id=r.json()['data']['id']
  # Update environment record with the latest scan relationship
  try:
    SC_API_ENVIRONMENTS_QUERY_ENDPOINT=f'{SC_API_ENDPOINT}/v1/environments?populate=component&filters[component][name][$contains]={component}'
    r = requests.get(SC_API_ENVIRONMENTS_QUERY_ENDPOINT, headers=sc_api_headers, timeout=10)
  except Exception as e:
    log.error(f"Error getting environments from SC for component {component}: {e}")
    return None

  if r.status_code == 200:
    for environment in r.json()["data"]:
      if environment['attributes']['build_image_tag'] == image_tag:
        environment_id = environment['id']
        try:
          r = requests.put(
            f'{SC_API_ENDPOINT}/v1/environments/{environment_id}',
            headers=sc_api_headers,
            json={'data': {'trivy_scan': trivy_scan_id}},
            timeout=10,
          )
          if r.status_code == 200:
            log.info(f"Updated environment record with Trivy scan result for {component} {image_tag}")
          else:
            log.error(f"Failed to update environment record with Trivy scan result for {component} {image_tag}: {r.status_code}")
        except Exception as e:
            log.error(f"Error updating environment record with Trivy scan result for {component} {image_tag}: {e}")

def extract_image_list(environments_data):
  filtered_components = []
  unique_components = set()

  for environment in environments_data:
    if 'component' in environment['attributes']:
      if environment['attributes']['build_image_tag'] is not None:
        component_name=environment['attributes']['component']['data']['attributes']['name']
        container_image_repo=environment['attributes']['component']['data']['attributes']['container_image']
        build_image_tag=environment['attributes']['build_image_tag']
        filtered_component = {
          'component_name': component_name,
          'container_image_repo': container_image_repo,
          'build_image_tag': build_image_tag
        }
        # Convert the dictionary to a tuple of items to make it hashable
        component_tuple = tuple(filtered_component.items())
        if component_tuple not in unique_components:
          unique_components.add(component_tuple)
          filtered_components.append(filtered_component)
        else:
          log.warning(f"{environment['attributes']['type']} environment found without build_image_tag: {component_name}")

  log.info(f"Number of environments records in SC: {len(environments_data)}")
  log.info(f"Number of images to scan: {len(filtered_components)}")
  return filtered_components

def run_trivy_scan(component):
  component_name = component['component_name']
  component_build_image_tag = component['build_image_tag']
  image_name = f"{component['container_image_repo']}:{component_build_image_tag}"
  log.info(f"Running Trivy scan on {image_name}")

  try:
    result = subprocess.run(
    [
        'trivy', 'image', image_name,
        '--severity', 'HIGH,CRITICAL',
        '--format', 'json',
        '--ignore-unfixed',
        '--skip-dirs', '/usr/local/lib/node_modules/npm',
        '--skip-files', '/app/agent.jar',
        '--cache-dir', cache_dir
    ],
    capture_output=True, text=True, check=True)
    scan_output = json.loads(result.stdout)
    results_section = scan_output.get("Results", [])
    # Check if there are any vulnerabilities
    has_vulnerabilities = any(result.get("Vulnerabilities") for result in results_section)

    # Display the appropriate message
    if has_vulnerabilities:
      result_json=results_section
    else:
      result_json={"message": "No vulnerabilities in container image"}

    log.info(f"Trivy scan result for {image_name}:\n{result_json}")
    upload_sc_trivy_scan_results(component_name, component_build_image_tag, result_json)
  except subprocess.CalledProcessError as e:
    log.error(f"Trivy scan failed for {image_name}: {e.stderr}")

def scan_prod_image(components):
  log.info(f'Starting scan for {len(components)} components...')
  threads = []

  for component in components:
    if not isinstance(component, dict):
      log.error(f"Invalid component format: {component}")
      continue

    if 'build_image_tag' in component and component['build_image_tag']:
      t = threading.Thread(target=run_trivy_scan, args=(component,))
      threads.append(t)

      # Start the thread
      t.start()
      log.info(f'Started thread for {component["component_name"]}')

      # Limit the number of active threads to MAX_THREADS
      while threading.active_count() > MAX_THREADS:
        log.debug(f'Active Threads={threading.active_count()}, Max Threads={MAX_THREADS}')
        sleep(1)

  # Wait for all threads to complete
  for t in threads:
    t.join()

  log.info('Completed all Trivy scans.')

def get_new_container_image_list(image_list):
  new_image_list = []
  trivy_data=fetch_sc_data(SC_API_TRIVY_SCANS_ENDPOINT)
  for image in image_list:
    build_image_tag = image['build_image_tag']
    if not any(trivy['attributes']['build_image_tag'] == build_image_tag for trivy in trivy_data):
      new_image_list.append(image)  
  return new_image_list

################# Main functions #################

if __name__ == '__main__':
  logging.basicConfig(format='[%(asctime)s] %(levelname)s %(threadName)s %(message)s', level=LOG_LEVEL)
  log = logging.getLogger(__name__)
  if '-f' in os.sys.argv or '--full' in os.sys.argv:
    log.info("Running Trivy scan on all container images in Service Catalogue")
    log.info("********************************************************************")
    incremental_scan=False
  elif '-i' in os.sys.argv or '--incremental' in os.sys.argv:
    log.info("Running Trivy scan on new images only")
    log.info("********************************************************************")
    incremental_scan=True
  else:
    log.error("Invalid argument. Use -i or --incremental for incremental scan or -f or --full for full scan")
    sys.exit(1)

  sc_api_headers = {
    'Authorization': f'Bearer {SC_API_TOKEN}',
    'Content-Type': 'application/json',
    'Accept': 'application/json',
  }

  # Test connection to Service Catalogue
  try:
    r = requests.head(
      f'{SC_API_ENVIRONMENTS_ENDPOINT}/_health', headers=sc_api_headers, timeout=10
    )
    log.info(f'Successfully connected to the Service Catalogue. {r.status_code}')
  except Exception as e:
    log.critical('Unable to connect to the Service Catalogue.')
    raise SystemExit(e) from e
  
  # Install Trivy
  install_trivy()

  # Fetch components data from Service Catalogue
  environments_data=fetch_sc_data(SC_API_ENVIRONMENTS_ENDPOINT)

  # Extract image list data from environments data
  image_list = extract_image_list(environments_data)
  if incremental_scan:
    image_list = get_new_container_image_list(image_list)
  else:
    delete_sc_trivy_scan_results()

  cache_dir = '/app/trivy_cache' if os.path.exists('/app/trivy_cache') else '/tmp'
  scan_prod_image(image_list)
