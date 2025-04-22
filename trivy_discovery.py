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
import globals
import utils.update_sc_scheduled_jobs as update_sc_scheduled_job


# SC_API_ENDPOINT = os.getenv('SERVICE_CATALOGUE_API_ENDPOINT')
# SC_API_TOKEN = os.getenv('SERVICE_CATALOGUE_API_KEY')
# SC_FILTER = os.getenv('SC_FILTER', '')
# SC_SORT = ''
# SC_API_ENVIRONMENTS_ENDPOINT = 'environments?populate=component'
# SC_API_TRIVY_SCANS_ENDPOINT = 'trivy-scans?populate=*'
# SLACK_ALERT_CHANNEL = os.getenv('SLACK_ALERT_CHANNEL', '')
# SLACK_BOT_TOKEN = os.getenv('SLACK_BOT_TOKEN', '')

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
    globals.job_name = 'hmpps-trivy-discovery-full'
    log.info('Running Trivy scan on all container images in Service Catalogue')
    log.info('********************************************************************')
  elif '-i' in os.sys.argv or '--incremental' in os.sys.argv:
    globals.job_name = 'hmpps-trivy-discovery-incremental'
    log.info('Running Trivy scan on new images only')
    log.info('********************************************************************')
  else:
    log.error(
      'Invalid argument. Use -i or --incremental for incremental scan or -f or --full for full scan'
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

  globals.services = Services(sc_params, slack_params, log)
  sc = globals.services.sc

  if not sc.connection_ok:
    log.error('Failed to connect to the Service Catalogue. Exiting...')
    globals.services.slack.alert('hmpps-trivy-discovery: failed to connect to the Service Catalogue')
    sys.exit(1)

  # Install Trivy
  trivy.install()
  image_list = trivy_scans.get_image_list()
  if globals.job_name == 'hmpps-trivy-discovery-full':
    trivy_scans.delete_sc_trivy_scan_results()
  
  trivy.scan_prod_image(image_list, max_threads)

  if globals.error_messages:
    update_sc_scheduled_job.process_sc_scheduled_jobs('Errors')
    log.info("SharePoint discovery job completed  with errors.")
  else:
    update_sc_scheduled_job.process_sc_scheduled_jobs('Succeeded')
    log.info("SharePoint discovery job completed successfully.")

if __name__ == '__main__':
  main()
