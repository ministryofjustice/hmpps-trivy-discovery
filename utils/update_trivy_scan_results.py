import os
from time import sleep
from datetime import datetime
from classes.service_catalogue import ServiceCatalogue
import globals 

def upload(component, image_tag, result):
  log = globals.services.log
  sc = globals.services.sc
  trivy_scan_data = {
    'name': component,
    'trivy_scan_results': result,
    'build_image_tag': image_tag,
    'trivy_scan_timestamp': datetime.now().isoformat(),
  }

  if response := sc.add(sc.trivy_scans_get, trivy_scan_data):
    trivy_scan_id = response.get('data', {}).get('id', {})
    if trivy_scan_id:
      # rather unpleasant workaround with the label field since it's underneath component
      if environments := sc.get_filtered_data('environments' , 'component][name', component):
        for environment in environments:
          if environment['attributes']['build_image_tag'] == image_tag:
            log.debug(f'environment: {environment}')
            environment_id = environment['id']
            try:
              sc.update('environments', environment_id, {'trivy_scan': trivy_scan_id})
              log.info(
                f'Updated environment {environment_id} with Trivy scan ID: {trivy_scan_id}'
              )
            except Exception as e:
              log.error(f'Failed to update environment {environment_id} with Trivy scan ID: {trivy_scan_id} - {e}')
              globals.error_messages.append(f'Failed to update environment {environment_id} with Trivy scan ID: {trivy_scan_id} - {e}')
      else:
        log.warning(f'No environments found for {component}')
    else:
      log.warning(f'No trivy_scan_id found for {component}')
  else:
    log.error(f'Failed to upload Trivy scan results for {component}: error code {response.status_code}')
    globals.error_messages.append(f'Failed to upload Trivy scan results for {component}: error code {response.status_code}')