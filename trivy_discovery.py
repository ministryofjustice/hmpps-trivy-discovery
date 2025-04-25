#!/usr/bin/env python
import os
import sys
import json
import logging
from datetime import datetime
from classes.service_catalogue import ServiceCatalogue
from classes.slack import Slack
import processes.trivy_scans as trivy_scans
import classes.trivy as trivy
from utilities.discovery import job
import processes.scheduled_jobs as sc_scheduled_job

# Set maximum number of concurrent threads to run, try to avoid secondary github api limits.
max_threads = 5
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO').upper()

class Services:
  def __init__(self, sc_params, slack_params, log):
    self.slack = Slack(slack_params, log)
    self.sc = ServiceCatalogue(sc_params, log)
    self.log = log

def main():
  logging.basicConfig(
    format='[%(asctime)s] %(levelname)s %(threadName)s %(message)s', level=LOG_LEVEL
  )
  log = logging.getLogger(__name__)
  if '-f' in os.sys.argv or '--full' in os.sys.argv:
    job.name = 'hmpps-trivy-discovery-full'
    log.info('Running Trivy scan on all container images in Service Catalogue')
    log.info('********************************************************************')
  elif '-i' in os.sys.argv or '--incremental' in os.sys.argv:
    job.name = 'hmpps-trivy-discovery-incremental'
    log.info('Running Trivy scan on new images only')
    log.info('********************************************************************')
  else:
    log.error(
      'Invalid argument. Use -i or --incremental for incremental scan or -f or --full for full scan.'
    )
    sys.exit(1)

  # service catalogue parameters
  sc_params = {
    'url': os.getenv('SERVICE_CATALOGUE_API_ENDPOINT'),
    'key': os.getenv('SERVICE_CATALOGUE_API_KEY'),
    'filter': os.getenv('SC_FILTER', ''),
  }

  # Slack parameters
  slack_params = {
    'token': os.getenv('SLACK_BOT_TOKEN'),
    'notify_channel': os.getenv('SLACK_NOTIFY_CHANNEL', ''),
    'alert_channel': os.getenv('SLACK_ALERT_CHANNEL', ''),
  }

  services = Services(sc_params, slack_params, log)
  sc = services.sc
  slack =services.slack

  if not sc.connection_ok:
    log.error('Failed to connect to the Service Catalogue. Exiting...')
    slack.alert('hmpps-trivy-discovery: failed to connect to the Service Catalogue')
    sys.exit(1)

  # Install Trivy
  trivy.install(services)
  image_list = trivy_scans.get_image_list(services)
  if job.name == 'hmpps-trivy-discovery-full':
    trivy_scans.delete_sc_trivy_scan_results(services)
  
  trivy.scan_prod_image(services, image_list, max_threads)

  if job.error_messages:
    sc_scheduled_job.update(services, 'Errors')
    log.info("Trivy discovery job completed  with errors.")
  else:
    sc_scheduled_job.update(services, 'Succeeded')
    log.info("Trivy discovery job completed successfully.")

if __name__ == '__main__':
  main()
