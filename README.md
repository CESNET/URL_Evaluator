# URL evaluator

Author: Michaela Novotna
Email: <xnovot2i@stud.fit.vutbr.cz>

A system composed of several components whose task is to retrieve suspicious URLs and perform their analysis and classification.
Firstly suspicious URLs have to be loaded into a database of this system.
After extracting suspicious URLs, the next step is to analyze and categorize them.
This process involves automatic evaluation to determine the classification of each URL.

URLs are categorized into one of four classes: malicious, harmless, unreachable, or unclassified.

The classification is based on various factors, including the presence of URLs on known blacklists,
assessments by antivirus engines, and analysis of downloaded content.
Despite this automated classification, some URLs may still be ambiguous and are thus labeled as unclassified.
These URLs will require manual review to determine their appropriate classification.
System includes a web interface for manual classification allowing browsing of data from the database, modification of certain information, and manual classification of URLs.

## Evaluator

The URL evaluator itself is a continuous program, launched with the command `python3 ./url_evaluator.py -c ./Config/config.yaml`. Before running, it is necessary to adjust the configuration in the file `./Config/config.yaml`.

## Helper Scripts

Contains the following scripts:

- `activity_status.py` - checks the activity status for all URLs in the URL evaluator database
- `cleanup_db.py` - removes outdated records from the database
- `create_db.py` - creates the database schema
- `honenetAsia2db.py` - retrieves new suspicious URLs from honeynet.Asia
- `send2urlhaus.py` - sends all malicious addresses to the URLhaus project
- `all_activity.py` - checks the activity status of all URLs in the MISP instance - typically not executed
- `evaluator2misp.py` - creates an event for the current day with newly discovered malicious addresses
- `misp_active_url.py` - updates the ids tag in MISP for URLs whose activity status has changed
- `misp2list.py` - creates a URL blacklist

A file `./cron/url_evaluator` is available for running all helper scripts via Cron. This file can be edited as needed, and it is also necessary to add API keys for specific tools.
For usage of each script run the script with argument `--help`.

## MISP

A lot of components of this system works with an MISP instance. New MISP object used in this system is defined in folder `./misp_objects`.

## NEMEA Modules

Modules for the NEMEA system are in the `./nemea_modules` directory. To use them, a running version of the NEMEA system is required.
For more information about NEMEA modules see `./nemea_modules/url_blacklist_filter/README.md` and `./nemea_modules/url_blacklist_filter/README.md`. Both modules should be running together.

## Run URL evaluator

1. Create database `sqlite3 /PATH/TO/DB/db.sqlite < ./scripts/db_scheme.sql`
2. Edit and configure `./Config/config.yaml`
3. Run script downloading suspicious URLs, list updates every day - `python ./scripts/honeynetAsia2db.py -d PATH_TO_DB`
4. Download URL blacklist (redownload in intervals to keep blacklist up-to-date) - `curl -s -S https://urlhaus.abuse.ch/downloads/text/ > PATH_TO_BLACKLIST`
5. Run URL evaluator `python ./url_evaluator.py -c PATH_TO_CONFIG_FILE`

## Web

Web interface made as tool for manual classification and going through already evaluated URLs.
Web allows to list all the URLs in system, see their detail information, and edit classification for each URL. It is posible to select multiple URLs and change their classification at once.

Files defining the web interface are located in the `./Web` directory. The behavior of the web is defined in the `template.py` file. To run the test version, the command can be used:

Note: You might need to change web config file `./Web/web_config.yaml` or path stored in variable `config_file` in file `./Web/template.py` for correct paths to be used. Without correcting those paths and other information working of app is not guaranteed.

```bash
cd Web
FLASK_APP=template.py FLASK_ENV=development flask run --debug
```

For permanent deployment of the web application, use Apache.
