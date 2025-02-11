# hmpps-trivy-discovery

Service that will run Trivy image scans on HMPPS container images and pushes the results into the service catalogue where they can be displayed in developer portal 

The app does the following:
- Retrieves a list of all components (microservices) from the service catalogue.
- For each component it fetches container image details for each environment.
- It then runs the Trivy container image scan and updates the service catalogue with can results. 

Results are visible via the developer portal, e.g.

https://developer-portal.hmpps.service.justice.gov.uk/components/trivy
