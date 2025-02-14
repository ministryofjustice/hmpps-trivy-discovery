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
import redis
from time import sleep

SC_API_ENDPOINT = os.getenv('SERVICE_CATALOGUE_API_ENDPOINT')
SC_API_TOKEN = os.getenv('SERVICE_CATALOGUE_API_KEY')
SC_FILTER = os.getenv('SC_FILTER', '')
SC_PAGE_SIZE = 10
SC_PAGINATION_PAGE_SIZE = f'&pagination[pageSize]={SC_PAGE_SIZE}'
SC_SORT = ''
SC_API_ENDPOINT = f'{SC_API_ENDPOINT}/v1/components?populate=environments,latest_commit{SC_FILTER}{SC_PAGINATION_PAGE_SIZE}{SC_SORT}'
# Set maximum number of concurrent threads to run, try to avoid secondary github api limits.
MAX_THREADS = 5
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO').upper()

# redis environments
redis_host = os.getenv("REDIS_ENDPOINT")
redis_port = int(os.getenv("REDIS_PORT"))
redis_tls_enabled = os.getenv("REDIS_TLS_ENABLED", 'False').lower() in ('true', '1', 't')
redis_token = os.getenv("REDIS_TOKEN", "")
redis_max_stream_length = int(os.getenv("REDIS_MAX_STREAM_LENGTH", "360"))

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

def fetch_all_sc_components_data():
  all_sc_components_data = []  
  try:
    r = requests.get(SC_API_ENDPOINT, headers=sc_api_headers, timeout=10)
  except Exception as e:
    log.error(f"Error getting team in the SC: {e}")
    return None

  if r.status_code == 200:
    j_meta = r.json()["meta"]["pagination"]
    log.debug(f"Got result page: {j_meta['page']} from SC")
    all_sc_components_data.extend(r.json()["data"])
  else:
    raise Exception(f"Received non-200 response from Service Catalogue: {r.status_code}")
    return None

  # Loop over the remaining pages and collect all data
  num_pages = j_meta['pageCount']
  for p in range(2, num_pages + 1):
    page = f"&pagination[page]={p}"
    r = requests.get(f"{SC_API_ENDPOINT}{page}", headers=sc_api_headers, timeout=10)
    if r.status_code == 200:
      log.debug(f"Got result page: {p} from SC")
      all_sc_components_data.extend(r.json()["data"])
    else:
      raise Exception(f"Received non-200 response from Service Catalogue: {r.status_code}")
      return None
  log.info(f"Number of components records in SC: {len(all_sc_components_data)}")
  return all_sc_components_data

def extract_image_list(components_data):
  filtered_components = []
  unique_components = set()

  for component in components_data:
    if 'environments' in component['attributes']:
      for environment in component['attributes']['environments']:
        if environment['build_image_tag'] is not None:
          filtered_component = {
            'component_name': component['attributes']['name'],
            'container_image_repo': component['attributes']['container_image'],
            'build_image_tag': environment['build_image_tag']
          }
          # Convert the dictionary to a tuple of items to make it hashable
          component_tuple = tuple(filtered_component.items())
          if component_tuple not in unique_components:
            unique_components.add(component_tuple)
            filtered_components.append(filtered_component)
          else:
            log.warning(f"{environment['type']} environment found without build_image_tag: {component['attributes']['name']}")

  log.info(f"Number of components records in SC: {len(components_data)}")
  log.info(f"Number of images to scan: {len(filtered_components)}")
  return filtered_components

def run_trivy_scan(component):
  image_name = f"{component['container_image_repo']}:{component['build_image_tag']}"
  log.info(f"Running Trivy scan on {image_name}")
  # Check if the scan result is already in the cache
  cache_key = f"trivy:scan:cache:{component['build_image_tag']}"
  if redis.exists(cache_key):
    log.info(f"Cache hit for {component['build_image_tag']}")
    cached_result = redis.json().get(cache_key)
    log.info(f"Trivy scan result for {image_name} (from cache):\n{json.dumps(cached_result, indent=2)}")
    return

  try:
    result = subprocess.run(
    [
        'trivy', 'image', image_name,
        '--severity', 'HIGH,CRITICAL',
        '--format', 'json',
        '--ignore-unfixed',
        '--skip-dirs', '/usr/local/lib/node_modules/npm',
        '--skip-files', '/app/agent.jar'
        '--cache-backend', redis_url,
        '--refresh'
    ],
    capture_output=True, text=True, check=True)
    scan_output = json.loads(result.stdout)
    results_section = scan_output.get("Results", [])
    # Check if there are any vulnerabilities
    has_vulnerabilities = any(result.get("Vulnerabilities") for result in results_section)

    # Display the appropriate message
    if has_vulnerabilities:
      result=json.dumps(results_section, indent=2)
    else:
        result=json.dumps({"message": "No vulnerabilities in container image"}, indent=2)
    log.info(f"Trivy scan result for {image_name}:\n{result}")
    # Update service catalogue with the scan result (Add in environment variable or scan )
    # look into cache for base image - faster
    # Store the scan result in the Redis cache
    redis.json().set(cache_key, '$', results_section)
  except subprocess.CalledProcessError as e:
    log.error(f"Trivy scan failed for {image_name}: {e.stderr}")

def scan_prod_image(components):
  log.info(f'Starting scan for {len(components)} components...')
  threads = []

  # Create root object for Trivy scan cache data if it doesn't exist
  if not redis.exists('trivy:scan:cache'):
    redis.json().set('trivy:scan:cache', '$', {})

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

################# Main functions #################

if __name__ == '__main__':
  logging.basicConfig(format='[%(asctime)s] %(levelname)s %(threadName)s %(message)s', level=LOG_LEVEL)
  log = logging.getLogger(__name__)
  sc_api_headers = {
    'Authorization': f'Bearer {SC_API_TOKEN}',
    'Content-Type': 'application/json',
    'Accept': 'application/json',
  }

  # Test connection to Service Catalogue
  try:
    r = requests.head(
      f'{SC_API_ENDPOINT}/_health', headers=sc_api_headers, timeout=10
    )
    log.info(f'Successfully connected to the Service Catalogue. {r.status_code}')
  except Exception as e:
    log.critical('Unable to connect to the Service Catalogue.')
    raise SystemExit(e) from e

  # Test connection to redis
  try:
    redis_connect_args = dict(
      host = redis_host,
      port = redis_port,
      ssl = redis_tls_enabled,
      ssl_cert_reqs = None,
      decode_responses = True
    )
    if redis_token:
      redis_connect_args.update(dict(password=redis_token))
      redis_url = f"redis://:{redis_token}@{redis_host}:{redis_port}"
    redis = redis.Redis(**redis_connect_args)
    redis.ping()
    log.info("Successfully connected to redis.")
    # Create root object for Trivy scan cache data if it doesn't exist
    if not redis.exists('trivy:scan:cache'):
        redis.json().set('trivy:scan:cache', '$', {})
  except Exception as e:
    log.critical("Unable to connect to redis.")
    raise SystemExit(e)
  
  # Install Trivy
  install_trivy()

  # Fetch components data from Service Catalogue
  copmponents_data=fetch_all_sc_components_data()

  # Extract image list data from components data
  image_list = extract_image_list(copmponents_data)

  # Run Trivy scan on the container images
  scan_prod_image(image_list)
