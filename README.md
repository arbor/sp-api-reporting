# api-reporting
Link to main Epic: [API Reporting - E-08932](https://www54.v1host.com/ArborNetworks/Epic.mvc/Summary?oidToken=Epic:667971)
## Pre-Requisites
1. Install `git`
2. Install `docker`

## Getting Started
1. Clone this repo - `git@git.arbor.net:sp/api-reporting.git`
1. Cd into repo - `cd api-reporting`
1. Start up - `docker-compose up -d`
1. Log into grafana - [https://localhost:3000] - default creds are `admin/admin`
1. Create postgres data source
  1. Host: `postgres`
  1. Database: `postgres`
  1. User: `postgres`
  1. Password: `postgres`
  1. TLS/SSL Mode: `disable`
