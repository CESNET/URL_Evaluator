# URL evaluator

A system composed of several components whose task is to retrieve suspicious URLs and perform their analysis and classification. It includes a web interface allowing browsing of data from the database, modification of certain information, and manual classification of URLs.

## Evaluator

The URL evaluator itself is a continuous program, launched with the command TODO. Before running, it is necessary to adjust the configuration in the file `./Config/config.yaml`.

## Helper Scripts

Contains the following scripts:

- `activity_status.py` - checks the activity status for all URLs in the URL evaluator database
- `cleanup_db.py` - removes outdated records from the database
- `create_db.py` - creates the database schema
- `honenetAsia2db.py` - retrieves new suspicious URLs from honeynet.Asia
- `send2urlhaus.py` - sends all malicious addresses to the URLhaus project
- `all_activity.py` - checks the activity status of all URLs in the MISP instance - typically not run
- `evaluator2misp.py` - creates an event for the current day with newly discovered malicious addresses
- `misp_active_url.py` - updates the ids tag in MISP for URLs whose activity status has changed
- `misp2list.py` - creates a URL blacklist

A file `./cron/url_evaluator` is available for running all helper scripts via Cron. This file can be edited as needed, and it is also necessary to add API keys for specific tools.

## Web

Files defining the web interface are located in the `./Web` directory. The behavior of the web is defined in the `template.py` file. To run the test version, the command can be used:

```bash
FLASK_APP=template.py FLASK_ENV=development flask run --debug
```

For permanent operation of the web application, use Apache.

## NEMEA Modules

Modules for the NEMEA system are in the `./nemea_modules directory`. To use them, a running version of the NEMEA system is required.
