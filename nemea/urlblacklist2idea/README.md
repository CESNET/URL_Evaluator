# URL blacklist reporter

This module receives network traffic data from the first module (`./nemea_modules/url_blacklist_filter/url_blacklist_filter`) and generates an alert message upon detecting an attempt to connect to a malicious address.
To create alert message, modul needs to connect to MISP instance and get more information about malicious URL from there.
Once the alert is created, the module formats it according to the required specifications and sends it to the Warden system. The Warden system then processes this alert further.

## Usage

```python3 urlblacklist2idea.py -u MISP-INSTANCE -k MISP-API-KEY -i IFC_SPEC  [-e EVALUATOR-PASSWORD]```

|Argument | Description |
|---|-----------|
|-h, \--help| show this help message and exit |\
|--misp_url MISP-INSTANCE, -u MISP-INSTANCE| URL of MISP instance. Required to get any information about URL. |
|--misp_key MISP-API-KEY, -k MISP-API-KEY| API key for MISP instance. Required to get any information about URL.|
|--evaluator_password EVALUATOR-PASSWORD, -e EVALUATOR-PASSWORD| Password for authentication to evaluator api. Optional to get more specific information about URL.|
|-T, --trap |Enable output via TRAP interface (JSON type with format id \"IDEA\"). Parameters are set using \"-i\" option as usual.|
|-c FILE,--config FILE | Specify YAML config file path which to load.|
|-d, --dry |Do not run, just print loaded config.|
|-W CONFIG_FILE, --warden CONFIG_FILE |Send IDEA messages to Warden server. Load configuration of Warden client from CONFIG_FILE.|
|-n NODE_NAME, --name NODE_NAME |Name of the node, filled into \"Node.Name\" element of the IDEA message.|
|-v VERBOSE_LEVEL, --verbose VERBOSE_LEVEL |Enable verbose mode (may be used by some modules, common part doesn\'t print anything). Level 1 logs everything, level 5 only critical errors. Level 0 doesn\'t log.|
|-D, --dontvalidate |Disable timestamp validation, i.e. allow timestamps to be far in the past or future.|

Common TRAP parameters: -i IFC_SPEC See
<http://nemea.liberouter.org/trap-ifcspec/> for more information.

## Description

Inputs: 1\
Outputs: 0\
Description: Converts output of url_blacklist_filter module
to IDEA. Connects to instance of MISP and gets additional information
about malicious URL.

### Input

Required format of input: \
UniRec: \
"ipaddr SRC_IP,time TIME_FIRST,time
TIME_LAST,uint64 BYTES,uint64 BYTES_REV,string HTTP_REQUEST_HOST,string
HTTP_REQUEST_URL,uint32 HTTP_RESPONSE_STATUS_CODE\"

### Output

All \'\<something\>2idea\' modules convert reports from various
detectors to Intrusion Detection Extensible Alert (IDEA) format. The
IDEA messages may be send or stored using various actions, see
<http://nemea.liberouter.org/reporting/> for more information.

## Data sources

This module retrieves information about malicious URLs from two sources - MISP and an optional URL evaluator. Providing the MISP instance as a parameter is mandatory for core functionality, while the URL evaluator serves as an optional additional information source.

### Data from MISP

- hash of content
- mime-type of content
- threat label

### Data from URL evaluator API

- content size
- note from manual evaluation