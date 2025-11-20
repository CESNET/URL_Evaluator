# URL Evaluator

Author: Michaela Novotna
Email: <xnovot2i@stud.fit.vutbr.cz>

URL Evaluator is a tool for semi-automatic analysis and classification of suspicious URLs.
The goal is to retrieve URLs from several honeypot projects and perform semi-automatic analysis and classification.
Currently we are processing data from:
* [CESNET Hugo](https://hugo.cesnet.cz/en/index)
* [CZ.NIC HaaS ](https://haas.nic.cz/)
* [HoneyNet Asia](https://blog.apnic.net/2019/09/17/the-apnic-community-honeynet-project/)
* GEANT T-Pot (an internal activity of GN5-2 project)

Firstly, data is sent to the system by one of the input modules and stored into a database.
After processing incoming data, the next step is to analyze and classify extracted URLs.
This process involves various classification methods, such as checking for presence on public blacklists, assessment by antivirus engines and analysis of downloaded content.
After the automated evaluation is finished, some URLs may still be left unclassified (e.g. if the analysis results are inconclusive) - these will require manual review by the user.
A web interface is available as a tool for manual classification and looking up evaluated URLs.
It allows users to browse the database, manually add new URLs, see detailed information and edit their classification.

### Classification schema

| Classification | Reason                     | Description                                                                                               |
|----------------|----------------------------|-----------------------------------------------------------------------------------------------------------|
| harmless       | VT URL check               | URL is listed on VirusTotal and meets the criteria to be classified as harmless                           | 
|                | VT file check              | URL content is listed on VirusTotal and meets the criteria to be classified as harmless                   | 
| malicious      | Blacklist check            | URL is listed on evaluation blacklist (URLhaus)                                                           | 
|                | MB file check              | URL content is listed on MalwareBazaar                                                                    | 
|                | VT URL check               | URL is listed on VirusTotal and meets the criteria to be classified as malicious                          | 
|                | VT file check              | URL content is listed on VirusTotal and meets the criteria to be classified as malicious                  | 
| unclassified   | Waiting for evaluation     | URL is yet to be evaluated                                                                                |
|                | No entry                   | URL (or its content) wasn't found by any classification sources                                           |
|                | VT URL check inconclusive  | URL is listed on VirusTotal, but doesn't meet the criteria to be classified as harmless/malicious         |
|                | VT file check inconclusive | URL content is listed on VirusTotal, but doesn't meet the criteria to be classified as harmless/malicious |
|                | VT limit exceeded          | VirusTotal rate limit was exceeded, URL will be re-evaluated later                                        |
|                | No content                 | URL has no content                                                                                        |
|                | File too large             | URL content is too large to be downloaded and analyzed                                                    |
| unreachable    | Connection refused         | URL is refusing connections                                                                               |
|                | Connection timeout         | Connection to URL timed out                                                                               |
|                | Too many redirects         | Connection to URL failed because of too many redirects                                                    |
|                | Status code <...>          | Connection to URL failed with specified status code                                                       |
| invalid        | Invalid format             | URL format is invalid                                                                                     |

## Main modules

URL Evaluator is composed of several components:
* Inputs
  * `warden2evaluator` - receives data from CESNET Hugo and CZ.NIC HaaS
  * `honeynetasia2evaluator` - receives data from HoneyNet Asia
  * `tpot2evaluator` - receives data from GEANT T-Pot
* Data processing
  * `activity_scanner` - periodically updates activity status of stored URLs
  * `db_cleaner` - deletes old records from the DB
* Classification pipeline
  * `evaluator` - continuously evaluates stored URLs
* Outputs
  * `evaluator2urlhaus` - sends malicious URLs to [URLhaus](https://urlhaus.abuse.ch/)
  * `evaluator2misp` - sends malicious URLs to MISP

## MISP integration

Evaluator can be configured to share information about discovered URLs via MISP.
To start sending data to MISP, configure the URL of your MISP instance and the API key in `/etc/url_evaluator/config.yaml`.
A new event will be created each day with newly discovered URLs that were classified as malicious.

## NEMEA integration

Evaluator can also be integrated with NEMEA to monitor access to malicious URLs.
NEMEA modules, scripts and config files are located in the `nemea` directory. To use them, a running instance of NEMEA is required.
For more information about NEMEA see https://github.com/CESNET/Nemea.

* **url_blacklist_filter** Detects access to blacklisted URLs (see [README](nemea/url_blacklist_filter/README.md))
* **urlblacklist2idea** Reporting module (see [README](nemea/urlblacklist2idea/README.md))
* **url_blacklist.sup** Config file for NEMEA supervisor
* **urlfilter.filter** Filter definition for UniRec Filter module (optional)

## Helper scripts

Additional scripts can be run via cron using the prepared template in `/etc/cron.d/url_evaluator`
 * `misp2nemea.py` - Downloads malicious URLs from Evaluator (via MISP) and URLhaus, and creates a combined blacklist for the detector module.

## Run URL evaluator

1. Download the installation script: [install_ol9.sh](https://raw.githubusercontent.com/CESNET/URL_Evaluator/master/install/install_ol9.sh) (written for Oracle Linux 9). 
1. Run the script as root. It'll download the latest version of URL Evaluator, install all requirements
   and configure everything which is possible to configure automatically.
1. Follow the instructions printed by the script to finish configuration.
   - Configure Warden client (you first need to register your client at Warden server to be able to receive data).
   - Create user accounts for web interface / API (only local accounts are supported, federated login (e.g. shibboleth) must be installed and configured manually if needed).
1. Review the main config file `/etc/url_evaluator/config.yaml` and edit as needed.
1. Run the supervisor `sudo systemctl start url-evaluator-supervisor` and manage backend using `evaluatorctl` or via `http://localhost:9001`
1. Check frontend at `https://<server_address>/url_evaluator/`

Note: You may need to edit Apache config in `/etc/httpd/conf.d/url_evaluator.conf` to suit your needs.

### Installation paths

* All the code (main modules, web, scripts) is installed into `/url_evaluator/`
* Configuration is located in `/etc/url_evaluator/`
* Logs go to `/var/log/url_evaluator/`
* Data is located in `/data/url_evaluator/`

## Publication

The tool was presented at Network Security Operations workshop at CNSM'24:
* M. Novotná and V. Bartoš, [URL Evaluator: Semi-automatic evaluation of suspicious URLs from honeypots](https://ieeexplore.ieee.org/abstract/document/10814604/).
  In 20th International Conference on Network and Service Management (CNSM 2024), Prague, Czech Republic, IFIP, 2024. (PDF: [paper](https://dl.ifip.org/db/conf/cnsm/cnsm2024/1571071957.pdf), [presentation slides](https://drive.google.com/file/d/13_w_WV5naYFWoykNANfaRwvJcrEjPLWU/view?usp=sharing))

## Acknowledgment

This work was partially supported by the [SOCCER project](https://soccer.agh.edu.pl/), which is funded under Grant Agreement No. 101128073 and supported by the European Cybersecurity Competence Centre.


