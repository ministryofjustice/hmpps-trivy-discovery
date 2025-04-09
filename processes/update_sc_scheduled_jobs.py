# Description: Update the status of a scheduled job in the Service Catalogue
import os
from time import sleep
from datetime import datetime
from classes.service_catalogue import ServiceCatalogue

log_level = os.environ.get('LOG_LEVEL', 'INFO').upper()

class Services:
  def __init__(self, sc_params, slack_params, log):
    self.sc = ServiceCatalogue(sc_params, log)
    self.log = log

def process_sc_scheduled_jobs(services, job_name, status):
  sc = services.sc
  log = services.log
  job_mapping = {
      'hmpps-trivy-discovery-full': sc.scheduled_jobs_trivy_discovery_full_get,
      'hmpps-trivy-discovery-incremental': sc.scheduled_jobs_trivy_discovery_incremental_get,
  }
  if job_name in job_mapping:
    sc_scheduled_jobs_data = sc.get_all_records(job_mapping[job_name])
  else:
    log.error(f"Job {job_name} not found in job mapping")
    return False

  job_data = {
    "last_run_successful": status,
    "last_scheduled_run": datetime.now().isoformat()
  }
  sc_scheduled_jobs_dict = {job['attributes']['name']: job for job in sc_scheduled_jobs_data}
  if job_name in sc_scheduled_jobs_dict:
    sc_scheduled_job = sc_scheduled_jobs_dict[job_name]
    sc_scheduled_job_id = sc_scheduled_job['id']
    sc.update('scheduled-jobs', sc_scheduled_job_id, job_data)
  else:
    log.error(f"Job {job_name} not found in Service Catalogue")
    return False
  return True