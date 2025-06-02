import logging
import os
import json
import requests
import re
import sys
from time import sleep
from datetime import datetime
from classes.slack import Slack
from classes.service_catalogue import ServiceCatalogue
from utilities.job_log_handling import log_debug, log_error, log_info, log_critical, log_warning, job
import processes.scheduled_jobs as sc_scheduled_job

def get_image_list(services, max_threads=10):
  sc = services.sc
  environments_data = sc.get_all_records(sc.environments_get)
  if not environments_data:
    log_error(f'Errors occurred while fetching environment data from Service Catalogue')
    sc_scheduled_job.update(services,'Failed')

  # Extract image list data from environments data
  image_list = extract_image_list(services, environments_data)
  if job.name == 'hmpps-trivy-discovery-incremental':
    image_list = get_new_container_image_list(services, image_list)
  return image_list
    
def delete_sc_trivy_scan_results(services):
  sc = services.sc
  log = services.log
  # Fetch the list of records
  trivy_data = sc.get_all_records(sc.trivy_scans_get)
  for record in trivy_data:
    record_id = record['id']
    try:
      sc.delete(sc.trivy_scans, record_id)
      log_info(f'Deleted Trivy scan record with ID: {record_id}')
    except requests.exceptions.RequestException as e:
      log_error(f'Error deleting Trivy scan record with ID {record_id}: {e}')
      job.error_messages.append(f'Error deleting Trivy scan record with ID {record_id}: {e}')

def get_new_container_image_list(services, image_list):
  sc = services.sc
  log = services.log
  new_image_list = []
  trivy_data = sc.get_all_records(sc.trivy_scans_get)
  filtered_trivy_data = [
    trivy for trivy in trivy_data
    if trivy['attributes'].get('scan_status') == 'Succeeded'
    or (
      trivy['attributes'].get('scan_status') == 'Failed'
      and all(
        "unable to find the specified image" in result.get('error', '').lower()
        for result in trivy['attributes'].get('trivy_scan_results', [])
      )
    )
  ]
  for image in image_list:
    build_image_tag = image['build_image_tag']
    name = image['component_name']
    if not any(
      trivy['attributes']['build_image_tag'] == build_image_tag and
      trivy['attributes']['name'] == name
      for trivy in filtered_trivy_data
    ):
      new_image_list.append(image)
  log_info(f'Number of new images to scan: {len(new_image_list)}')
  return new_image_list

def extract_image_list(services, environments_data):
  log = services.log
  filtered_components = []
  unique_components = set()

  for environment in environments_data:
    if component := environment.get('attributes', {}).get('component', {}):
      component_data = component.get('data', {})
      component_attributes = (
        component_data.get('attributes', {}) if component_data else {}
      )
      component_name = component_attributes.get('name')

      build_image_tag = environment.get('attributes', {}).get('build_image_tag')
      if not build_image_tag:
        build_image_tag = 'latest'
        log_warning(
          f'Build image tag for {component_name} is "latest", this may cause issues with image identification.'
        )
      container_image_repo = component_attributes.get('container_image')
      if container_image_repo:
        log_debug(
          f'environment build image tag for {component_attributes.get("name")}: {environment.get("attributes").get("build_image_tag")}'
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
        namespace = environment.get('attributes', {}).get('namespace')
        env_name = environment.get('attributes', {}).get('name')
        if component_name:
          log_warning(f'No container image repo for {component_name} - {env_name} - {namespace}')
        else:
          log_info(f'Orphaned environment record for namespace {env_name} - {namespace}')

  log_info(f'Number of environments records in SC: {len(environments_data)}')
  log_info(f'Number of images: {len(filtered_components)}')
  return filtered_components

def update(services, component, image_tag, result, scan_summary, scan_status = 'Succeeded'):
  log = services.log
  sc = services.sc
  MAX_SIZE = 1000000

  serialized_result = json.dumps(result)
  result_size = len(serialized_result.encode('utf-8'))
  if result_size > MAX_SIZE:
    result.clear()  # Remove all content from the result
    result.append({
        "error": (
            "Sorry, results too big. Please run the scan locally to get the raw data: "
            "trivy image ghcr.io/ministryofjustice/hmpps-service-catalogue:latest"
        )
    })

  trivy_scan_data = {
    'name': component,
    'trivy_scan_results': result,
    'build_image_tag': image_tag,
    'trivy_scan_timestamp': datetime.now().isoformat(),
    'scan_summary': scan_summary,
    'scan_status': scan_status
  }

  if response := sc.add(sc.trivy_scans_get, trivy_scan_data):
    trivy_scan_id = response.get('data', {}).get('id', {})
    if trivy_scan_id:
      # rather unpleasant workaround with the label field since it's underneath component
      if environments := sc.get_filtered_data('environments' , 'component][name', component):
        for environment in environments:
          if environment['attributes']['build_image_tag'] == image_tag:
            log_debug(f'environment: {environment}')
            environment_id = environment['id']
            try:
              sc.update('environments', environment_id, {'trivy_scan': trivy_scan_id})
              log_info(
                f'Updated environment {environment_id} with Trivy scan ID: {trivy_scan_id}'
              )
            except Exception as e:
              log_error(f'Failed to update environment {environment_id} with Trivy scan ID: {trivy_scan_id} - {e}')
      else:
        log_warning(f'No environments found for {component}')
    else:
      log_warning(f'No trivy_scan_id found for {component}')
  else:
    log_error(f'Failed to upload Trivy scan results for {component}: error code {response.status_code}')
    