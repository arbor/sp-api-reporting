## Overview
This tool extracts data about Alerts and Mitigations from Sightline via its APIs and loads it into a postgres database. Grafana is used to visualize that data. The tool uses docker compose to create three docker containers:

1. `sp-ingest` - Python code that extracts data from Sightline and loads it into PostgreSQL
2. `postgres` - PostgreSQL database for storage
3. `grafana` - Grafana for visualizing the data

## Pre-Requisites
1. Install `git`
2. Install `docker`

## Getting Started
1. Clone this repo - `https://github.com/arbor/sp-api-reporting`
1. Go into top level directory of this repo - `cd api-reporting`
1. Edit `.env` file and add the SP DNS/IP and [API token](#generate-an-api-token)
1. Start up - `docker compose up -d`
1. Initial extract could take a while - many minutes to an hour - depending on the amount of data. [Wait for `sp-ingest` to perform the initial extract.](#wait-for-initial-extract)
1. Log into grafana - [http://localhost:3000] - default creds are `admin/admin`
1. Click on the `Dashboards` icon on the left (four squares), and select the `Sightline: Alert EVENT - Statistics` dashboard (Under the `General` folder)

### Generate an API Token
Instructions can be found via the following:

1. Log into Sightline
1. Go to `Administration` --> `Sightline REST API Documentation`
1. Click on `Generating and managing REST API tokens` link and follow instructions

### Wait for initial extract
Type `docker compose logs -f sp-ingest` to follow the logs and wait until you see a log message:

```
api-reporting-sp-ingest-1  | INFO:root:DONE
api-reporting-sp-ingest-1  | INFO:root:## Sleeping for 86400 seconds
```
Type `Ctrl+C` to exit from following the logs.

## Cheat Sheet
NOTE: All commands should be run at the top level of this repository.
### Create and start tool
`docker compose up -d`
### Stop the tool
`docker compose stop`
### Start the tool back up
`docker compose start`
### View the `sp-ingest` log
`docker compose logs sp-ingest`
### Connect to `postgres` database
`docker compose exec -it postgres psql -U postgres` 
### Stop the tool and delete the data
NOTE: Running this command will delete ALL of the data in postgres. It will NOT delete any data from Sightline

`docker compose down`

## More Info
* [Provision Grafana](https://grafana.com/docs/grafana/latest/administration/provisioning/)
* [Docker Compose](https://docs.docker.com/compose/)
