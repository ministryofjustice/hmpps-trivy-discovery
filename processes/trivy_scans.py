import requests
import json
from datetime import datetime
from hmpps.services.job_log_handling import (
  log_debug,
  log_error,
  log_info,
  log_warning,
  job,
)


def get_image_list(sc):
  environments_data = sc.get_all_records(sc.environments_get)
  if not environments_data:
    log_error('Errors occurred while fetching environment data from Service Catalogue')
    sc.update_scheduled_job('Failed')
    return None

  # Extract image list data from environments data
  image_list = extract_image_list(environments_data)
  if job.name == 'hmpps-trivy-discovery-incremental':
    image_list = get_new_container_image_list(sc, image_list)
  return image_list


def delete_sc_trivy_scan_results(sc):
  # Fetch the list of records
  trivy_data = sc.get_all_records('trivy-scans')
  for record in trivy_data:
    if job.name == 'hmpps-trivy-discovery-incremental':
      if not record.get('name', '').startswith('hmpps-base-container-images'):
        continue

    record_document_id = record.get('documentId')
    try:
      sc.delete('trivy-scans', record_document_id)
      log_info(f'Deleted Trivy scan record with ID: {record_document_id}')
    except requests.exceptions.RequestException as e:
      log_error(f'Error deleting Trivy scan record with ID {record_document_id}: {e}')
      job.error_messages.append(
        f'Error deleting Trivy scan record with ID {record_document_id}: {e}'
      )


def get_new_container_image_list(sc, image_list):
  new_image_list = []
  trivy_data = sc.get_all_records('trivy-scans?populate=*')
  filtered_trivy_data = [
    trivy
    for trivy in trivy_data
    if trivy.get('scan_status') == 'Succeeded'
    or (
      trivy.get('scan_status') == 'Failed'
      and all(
        'unable to find the specified image' in result.get('error', '').lower()
        for result in trivy.get('trivy_scan_results', [])
      )
    )
  ]
  for image in image_list:
    build_image_tag = image['build_image_tag']
    name = image['component_name']
    if not any(
      trivy.get('build_image_tag') == build_image_tag and trivy.get('name') == name
      for trivy in filtered_trivy_data
    ):
      new_image_list.append(image)
  log_info(f'Number of new images to scan: {len(new_image_list)}')
  return new_image_list


def extract_image_list(environments_data):
  filtered_components = []
  unique_components = set()

  for environment in environments_data:
    if component := environment.get('component', {}):
      component_name = component.get('name')
      if component.get('archived'):
        log_debug(f'Skipping archived component: {component_name}')
        continue
      build_image_tag = environment.get('build_image_tag')
      if not build_image_tag:
        build_image_tag = 'latest'
        log_warning(
          f'Build image tag for {component_name} is "latest", '
          'this may cause issues with image identification.'
        )
      container_image_repo = component.get('container_image')
      if container_image_repo:
        log_debug(
          f'environment build image tag for {component.get("name")}: '
          f'{environment.get("build_image_tag")}'
        )
        filtered_component = {
          'component_name': component_name,
          'container_image_repo': container_image_repo,
          'build_image_tag': build_image_tag,
        }
        log_debug(f'filtered_component: {filtered_component}')
        component_tuple = tuple(filtered_component.items())
        if component_tuple not in unique_components:
          unique_components.add(component_tuple)
          filtered_components.append(filtered_component)
      else:
        namespace = environment.get('namespace')
        env_name = environment.get('name')
        if component_name:
          log_warning(
            f'No container image repo for {component_name} - {env_name} - {namespace}'
          )
        else:
          log_info(
            f'Orphaned environment record for namespace {env_name} - {namespace}'
          )

  log_info(f'Number of environments records in SC: {len(environments_data)}')
  log_info(f'Number of images: {len(filtered_components)}')
  return filtered_components


def update(sc, component, image_tag, image_id, scan_summary, scan_status='Succeeded'):
  trivy_scan_data = {
    'name': component,
    'build_image_tag': image_tag,
    'image_id': image_id,
    'trivy_scan_timestamp': datetime.now().isoformat(),
    'scan_summary': scan_summary,
    'scan_status': scan_status,
    'environments': [],
  }

  if 'hmpps-base-container-images' in trivy_scan_data.get('name', ''):
    trivy_scan_data['environments'] = ['unknown']
    response = sc.add('trivy-scans', trivy_scan_data)
    log_info(f'Added Trivy scan for {trivy_scan_data["name"]} to Service Catalogue.')
    return

  environments = sc.get_filtered_records('environments', 'component][name', component)
  environment_names = []
  environment_document_ids = []
  missing_images_environments_ids = []
  if image_tag == 'latest':
    environment_names.append('unknown')
    for environment in environments:
      missing_images_environments_ids.append(environment.get('documentId'))
  else:
    for environment in environments:
      if environment.get('build_image_tag') == image_tag:
        document_id = environment.get('documentId')
        environment_names.append(environment.get('name'))
        environment_document_ids.append(document_id)
  trivy_scan_data['environments'] = environment_names
  log_info(
    f'Scan data upload size for {component}: '
    f'{int(len(json.dumps(trivy_scan_data.get("scan_summary", {}))) / 1024)}kB'
  )
  if response := sc.add('trivy-scans', trivy_scan_data):
    trivy_scan_document_id = response.get('data', {}).get('documentId', '')

    if trivy_scan_document_id:
      # it will skip this if there aren't any
      for environment_document_id in environment_document_ids:
        sc.update(
          'environments',
          environment_document_id,
          {'trivy_scan': trivy_scan_document_id},
        )
        log_info(
          f'Updated environment {environment_document_id} with Trivy scan ID: '
          f'{trivy_scan_document_id}'
        )
      # it will skip this if there aren't any
      for environment_document_id in missing_images_environments_ids:
        sc.update(
          'environments',
          environment_document_id,
          {'trivy_scan': trivy_scan_document_id},
        )
        log_info(
          f'Updated environment {environment_document_id} with Trivy scan ID: '
          f'{trivy_scan_document_id}'
        )

      if not (environment_document_ids and missing_images_environments_ids):
        log_warning(f'No environments found for {component}')
    else:
      log_warning(f'No trivy_scan_document_id found for {component}')


def send_summary_to_slack(sc, slack):
  trivy_data = sc.get_all_records('trivy-scans?populate=*')
  if not trivy_data:
    log_warning('No Trivy scan data found to summarize.')
    return

  total_images = len(trivy_data)
  total_vulnerabilities = 0
  base_image_total_vulnerabilities = 0
  severity_count = {
    'CRITICAL': 0,
    'HIGH': 0,
    'MEDIUM': 0,
    'LOW': 0,
    'UNKNOWN': 0,
  }
  base_image_severity_count = {
    'CRITICAL': 0,
    'HIGH': 0,
    'MEDIUM': 0,
    'LOW': 0,
    'UNKNOWN': 0,
  }
  failed_scans = []
  error_messages = []

  for record in trivy_data:
    base_image_name = record.get('name', 'Unknown Image')
    scan_status = record.get('scan_status', 'Unknown')
    if scan_status == 'Succeeded':
      summary = record.get('scan_summary', {}).get('summary', {})
      os_pkgs = summary.get('os-pkgs', {})
      lang_pkgs = summary.get('lang-pkgs', {})
      for pkg_type in [os_pkgs, lang_pkgs]:
        for status in ['fixed', 'unfixed']:
          for severity, count in pkg_type.get(status, {}).items():
            severity_count[severity] += count
            total_vulnerabilities += count
            if base_image_name.startswith('hmpps-base-container-image'):
              base_image_severity_count[severity] += count
              base_image_total_vulnerabilities += count

  summary_message = (
    f'*Trivy Scan Summary:*\n'
    f'- Total Images Scanned: {total_images}\n'
    f'- Total Vulnerabilities Found: {total_vulnerabilities}\n'
    f'  - Critical: {severity_count["CRITICAL"]}\n'
    f'  - High: {severity_count["HIGH"]}\n'
    f'  - Medium: {severity_count["MEDIUM"]}\n'
    f'  - Low: {severity_count["LOW"]}\n'
    f'  - Unknown: {severity_count["UNKNOWN"]}\n'
    f' Base container images vulnerabilities:\n'
    f'  - Total Vulnerabilities Found: {base_image_total_vulnerabilities}\n'
    f'    - Critical: {base_image_severity_count["CRITICAL"]}\n'
    f'    - High: {base_image_severity_count["HIGH"]}\n'
    f'    - Medium: {base_image_severity_count["MEDIUM"]}\n'
    f'    - Low: {base_image_severity_count["LOW"]}\n'
    f'    - Unknown: {base_image_severity_count["UNKNOWN"]}\n'
  )

  if failed_scans:
    summary_message += f'\n*Failed Scans:* {", ".join(failed_scans)}\n'

  if error_messages:
    summary_message += '\n*Error Messages:*\n' + '\n'.join(error_messages)
  log_info('Summary of Trivy scans prepared for Slack notification.')
  log_info('Summary message:\n' + summary_message)
  summary_message += (
    '\n_(generated by <https://github.com/ministryofjustice/'
    'hmpps-trivy-discovery|hmpps-trivy-discovery>)_'
  )
  if job.name == 'hmpps-trivy-discovery-full':
    slack.notify(summary_message)

  if base_image_severity_count['CRITICAL'] > 0:
    alert_message = (
      f'*Alert: Significant Vulnerabilities in Base Container Images!*\n'
      f'- Critical: {base_image_severity_count["CRITICAL"]}\n'
      f'- High: {base_image_severity_count["HIGH"]}\n'
      f'- Medium: {base_image_severity_count["MEDIUM"]}\n'
      f'- Low: {base_image_severity_count["LOW"]}\n'
      f'Immediate action is recommended to address these vulnerabilities.'
      f'\n_(generated by '
      '<https://github.com/ministryofjustice/hmpps-trivy-discovery|hmpps-trivy-discovery>)_'
    )
    slack.alert(alert_message)
    log_info('Sent slack alert for significant vulnerabilities in base images.')
