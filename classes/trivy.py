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
from utilities.job_log_handling import log_debug, log_error, log_info, log_critical, job
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
    if not trivy_version:
      log_error('Failed to retrieve Trivy version')
      sc_scheduled_job.update(services, 'Failed')
      services.slack.alert('hmpps-trivy-discovery: failed to install Trivy - Failed to retrieve version')
      raise SystemExit('Failed to retrieve Trivy version')
    
    log_info(f'Trivy version: {trivy_version}')
    trivy_version_stripped = trivy_version.lstrip('v')
    # Define the URL for the Trivy binary
    trivy_url = f'https://github.com/aquasecurity/trivy/releases/download/{trivy_version}/trivy_{trivy_version_stripped}_Linux-64bit.tar.gz'
    trivy_tar = f'trivy_{trivy_version_stripped}_Linux-64bit.tar.gz'

    # Download the Trivy binary
    log_info(f'Downloading Trivy from {trivy_url}...')
    urllib.request.urlretrieve(trivy_url, trivy_tar)

    # Extract the tar.gz file
    log_info('Extracting Trivy...')
    with tarfile.open(trivy_tar, 'r:gz') as tar:
      tar.extractall()
    log_info('Trivy installed successfully.')

  except subprocess.CalledProcessError as e:
    log_error(f'Failed to install Trivy: {e}', file=sys.stderr)
    sc_scheduled_job.update(services, 'Failed')
    services.slack.alert(f'hmpps-trivy-discovery: failed to install Trivy - {e}')
    raise SystemExit(e) from e

def scan_image(services, component, cache_dir, retry_count):
  component_name = component['component_name']
  component_build_image_tag = component['build_image_tag']
  image_name = f'{component["container_image_repo"]}:{component_build_image_tag}'
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
        'vuln,secret,config',
        '--image-config-scanners',
        'misconfig,secret',
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
    # Commented temporarily to save all results 
    # if has_vulnerabilities:
    #   result_json = results_section
    # else:
    #   result_json.append({'message': 'No vulnerabilities in container image'})
    result_json = results_section
    log_info(f'Trivy scan result for {image_name}:\n{result_json}')
    scan_summary = scan_result_summary(result_json)
    trivy_scans.update(services, component_name, image_name, component_build_image_tag, result_json, scan_summary)
  except subprocess.CalledProcessError as e:
    result_json = []
    if "DB error" in e.stderr and retry_count <= 3:
      retry_count += 1
      log_info(f"Retrying Trivy scan for {image_name} - attempt {retry_count}...")
      sleep(5)
      scan_image(services, component, cache_dir, retry_count)
    else:
      log_error(f'Trivy scan failed for {image_name}: {e.stderr}')
      if "Fatal error" in e.stderr:
        fatal_error_match = re.search(r"FATAL\s+(.*)", e.stderr)
        fatal_error_message = fatal_error_match.group(1)
        result_json.append({"error": fatal_error_message})
      else:
        result_json.append({"error": e.stderr})
      scan_summary = {}
      trivy_scans.update(services, component_name, image_name, component_build_image_tag, result_json, scan_summary, 'Failed')

def scan_result_summary(scan_result):
  scan_summary = {
      "scan_summary": {
          "scan_result": {},
          "summary": {
              "os-pkgs": {"fixed": {}, "unfixed": {}},
              "lang-pkgs": {"fixed": {}, "unfixed": {}},
              "config": {},
              "secret": {}
          }
      }
  }
  def increment_summary(summary_section, severity, fixed=False):
    key = "fixed" if fixed else "unfixed"
    if key not in summary_section:
        summary_section[key] = {}
    summary_section[key][severity] = summary_section[key].get(severity, 0) + 1
        
  for result in scan_result:
    if not isinstance(result, dict):
        raise ValueError(f"Unexpected data type for result: {type(result)}. Expected a dictionary.")

    vulnerabilities = result.get("Vulnerabilities", [])
    misconfigurations = result.get("Misconfigurations", [])
    secrets = result.get("Secrets", [])

    # Process vulnerabilities (os-pkgs and lang-pkgs)
    if vulnerabilities:
        for vuln in vulnerabilities:
            class_type = "os-pkgs" if result.get("Type") == "os-pkgs" else "lang-pkgs"
            scan_summary["scan_summary"]["scan_result"].setdefault(class_type, []).append({
                "PkgName": vuln.get("PkgName", "N/A"),
                "Severity": vuln.get("Severity", "UNKNOWN"),
                "Description": vuln.get("Description", "N/A"),
                "InstalledVersion": vuln.get("InstalledVersion", "N/A"),
                "FixedVersion": vuln.get("FixedVersion", "N/A"),
                "VulnerabilityID": vuln.get("VulnerabilityID", "N/A")
            })
            increment_summary(
                scan_summary["scan_summary"]["summary"][class_type],
                vuln.get("Severity", "UNKNOWN"),
                fixed=bool(vuln.get("FixedVersion"))
            )

    # Process misconfigurations (config)
    if misconfigurations:
        for misconfig in misconfigurations:
            scan_summary["scan_summary"]["scan_result"].setdefault("config", []).append({
                "Severity": misconfig.get("Severity", "UNKNOWN"),
                "Description": misconfig.get("Message", "N/A"),
                "FilePath": result.get("Target", "N/A"),
                "LineNumber": misconfig.get("PrimaryResource", {}).get("Line", "N/A"),
                "AdditionalContext": misconfig.get("Resolution", "N/A")
            })
            severity = misconfig.get("Severity", "UNKNOWN")
            scan_summary["scan_summary"]["summary"]["config"][severity] = scan_summary["scan_summary"]["summary"]["config"].get(severity, 0) + 1

    # Process secrets (secret)
    if secrets:
        for secret in secrets:
            scan_summary["scan_summary"]["scan_result"].setdefault("secret", []).append({
                "Severity": secret.get("Severity", "UNKNOWN"),
                "Description": secret.get("Title", "N/A"),
                "FilePath": result.get("Target", "N/A"),
                "LineNumber": secret.get("StartLine", "N/A"),
                "AdditionalContext": secret.get("Match", "N/A")
            })
            severity = secret.get("Severity", "UNKNOWN")
            scan_summary["scan_summary"]["summary"]["secret"][severity] = scan_summary["scan_summary"]["summary"]["secret"].get(severity, 0) + 1
  return scan_summary

def scan_prod_image(services, components, max_threads):
  sc = services.sc
  log_info(f'Starting scan for {len(components)} components...')
  threads = []

  for component in components:
    if not isinstance(component, dict):
      log_error(f'Invalid component format: {component}')
      continue

    if 'build_image_tag' in component and component['build_image_tag']:
      initial_retry_count = 1
      t = threading.Thread(target=scan_image, args=(services, component, cache_dir, initial_retry_count))
      threads.append(t)

      # Start the thread
      t.start()
      log_info(f'Started thread for {component["component_name"]}')

      # Limit the number of active threads to max_threads
      while threading.active_count() > max_threads:
        log_debug(
          f'Active Threads={threading.active_count()}, Max Threads={max_threads}'
        )
        sleep(1)

  # Wait for all threads to complete
  for t in threads:
    t.join()

  log_info('Completed all Trivy scans.')

