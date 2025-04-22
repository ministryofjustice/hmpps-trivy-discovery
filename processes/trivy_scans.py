import logging
import os
import json
import requests
import re
from time import sleep
from datetime import datetime
from classes.slack import Slack
from classes.service_catalogue import ServiceCatalogue
import globals
import utils.update_sc_scheduled_jobs as update_sc_scheduled_job

def get_image_list(max_threads=10):
  sc = globals.services.sc
  environments_data = sc.get_all_records(sc.environments_get)
  if not environments_data:
    globals.error_messages.append(f'Errors occurred while fetching environment data from Service Catalogue')
    update_sc_scheduled_job.process_sc_scheduled_jobs('Failed')

  # Extract image list data from environments data
  image_list = extract_image_list(environments_data)
  if globals.job_name == 'hmpps-trivy-discovery-incremental':
    image_list = get_new_container_image_list(image_list)
  return image_list
    
def delete_sc_trivy_scan_results():
  sc = globals.services.sc
  log = globals.services.log
  # Fetch the list of records
  trivy_data = sc.get_all_records(sc.trivy_scans_get)
  for record in trivy_data:
    record_id = record['id']
    try:
      sc.delete(sc.trivy_scans, record_id)
      log.info(f'Deleted Trivy scan record with ID: {record_id}')
    except requests.exceptions.RequestException as e:
      log.error(f'Error deleting Trivy scan record with ID {record_id}: {e}')
      globals.error_messages.append(f'Error deleting Trivy scan record with ID {record_id}: {e}')

def get_new_container_image_list(image_list):
  sc = globals.services.sc
  log = globals.services.log
  new_image_list = []
  trivy_data = sc.get_all_records(sc.trivy_scans_get)
  for image in image_list:
    build_image_tag = image['build_image_tag']
    if not any(
      trivy['attributes']['build_image_tag'] == build_image_tag for trivy in trivy_data
    ):
      new_image_list.append(image)
  log.info(f'Number of new images to scan: {len(new_image_list)}')
  return new_image_list

def extract_image_list(environments_data):
  log = globals.services.log
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
