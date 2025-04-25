#!/usr/bin/python3

# In case we are in nemea/modules/report2idea/ and we want to import from repo:
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "nemea", "Nemea-Framework", "pycommon"))

import argparse
import requests
from pymisp import ExpandedPyMISP
from requests.auth import HTTPBasicAuth
import logging
import urllib3

# The whole functionality of reporting is here:
from report2idea import *

# TODO: Ping MISP and URL Evaluator on start (if keys are given) to check the connection works.
#   However, this needs the possibility to define some init() function to be called by the common part of the report2idea.

# Moudle name, description and required input data format
MODULE_NAME = "urlblacklist2idea"
MODULE_DESC = "Converts output of url_blacklist_filter module to IDEA."
REQ_TYPE = pytrap.FMT_UNIREC
REQ_FORMAT = "ipaddr SRC_IP,time TIME_FIRST,time TIME_LAST,uint64 BYTES,uint32 PACKETS,string HTTP_REQUEST_HOST,string HTTP_REQUEST_URL,uint32 HTTP_RESPONSE_STATUS_CODE"

# Set logger (format and verbosity level should be set by the common part of report2idea)
logger = logging.getLogger("urlblacklist2idea")


def create_msg(rec, details):
    """
    Create message for IDEA.
    
    details - dictionary with details about url
    """

    msg = f"IP {rec.SRC_IP} connected to URL http://{rec.HTTP_REQUEST_HOST + rec.HTTP_REQUEST_URL}"

    if rec.HTTP_RESPONSE_STATUS_CODE == 0: # in case of unidirectional flows, we don't know the response code (the field is set to 0).
        msg = msg + "."
    elif 200 <= rec.HTTP_RESPONSE_STATUS_CODE < 300:
        msg = msg + " and successfully downloaded some content."
    elif rec.HTTP_RESPONSE_STATUS_CODE >= 400:
        msg = msg + f", but it seems it failed to download the content (response code {rec.HTTP_RESPONSE_STATUS_CODE})."
    else: # 3xx (redirection) or 1xx (informational, doesn't occur normally)
        msg = msg + f", but we don't know if it downloaded any content (response code {rec.HTTP_RESPONSE_STATUS_CODE})."

    classification = details.get("classification", None)
    if classification == "malicious":
        if details.get("threat_label"):
            msg = msg + f" This URL is known to host a malware ({details.get('threat_label')})."
        else:
            msg = msg + " This URL is known to host a malware."
        if 200 <= rec.HTTP_RESPONSE_STATUS_CODE < 300:
            msg = msg + " If the content was executed, the host may now be infected."
        else:
            msg = msg + " If the connection was successful and the content executed, the host may now be infected."
    elif classification == "miner":
        msg = msg + " This URL is known to host a crypto miner."

    return msg



def get_evaluator_info(url, details, evaluator_passwd):
    """
    Get information about a URL from the Evaluator database.
    
    url - URL to search in the Evaluator database
    details - dictionary to store information about url
    evaluator_passwd - password to the Evaluator API
    """
    logger.info("Getting info from URL Evaluator")

    try:
        r = requests.get("https://var.liberouter.org/private/url_evaluator/api/url_stats", params={"url": url}, auth = HTTPBasicAuth('url_evaluator', evaluator_passwd))
        if r.status_code != 200:
            logger.info("No data found in URL Evaluator")
            return
        json_string = r.content.decode('utf-8')
        data_dict = json.loads(json_string)

        if data_dict['note']:
            details['note'] = data_dict['note']
        if data_dict['content_size']:
            details['content_size'] = data_dict['content_size']

    except Exception as e:
        logger.error(f"Error getting info from URL Evaluator for URL '{url}': ({type(e)}) {e}")
        return
    logger.info("URL Evaluator data found")


def get_misp_info(url, misp_url, misp_key, details):
    """
    Get information about url from MISP instance.
    
    url - url to search in MISP
    misp_url - url of MISP instance
    misp_key - API key for MISP instance
    details - dictionary to store information about url
    """
    logger.info("Getting info from MISP")

    # get objects from misp
    # TODO: TLS validation is disabled - it's ok for us, now, but it should be made optional (validation enabled by default)
    urllib3.disable_warnings() # suppress warnings about HTTPS connections with disabled certificate validation
    try:
        misp = ExpandedPyMISP(misp_url, misp_key, ssl=False, debug=False)
        misp_attribute = misp.search(controler="objects", limit=1, value=url, type_attribute="url", include_context=False)
    except Exception as e:
        logger.error(f"Error getting info from MISP for URL '{url}': ({type(e)}) {e}")
        return

    # if no object was found, return
    if len(misp_attribute) == 0:
        logger.debug("No data found in MISP")
        return
    
    misp_obj = None

    # get required object
    for obj in misp_attribute[0]["Event"].get("Object"):
        for attr in obj.get("Attribute"):
            if attr.get("type") == "url" and attr.get("value") == url:
                misp_obj = obj
                break

    # if no object was found, return
    if not misp_obj:
        logger.info("No data found in MISP")
        return

    # get information from object
    for attr in misp_obj.get("Attribute"):
        misp_attr_type = attr.get("type")
        obj_relation = attr.get("object_relation")
        if misp_attr_type == "sha1" or misp_attr_type == "sha256" or misp_attr_type == "md5":
            details["hash"] = misp_attr_type + ":" + attr.get("value")
        elif misp_attr_type == "mime-type":
            details["mime_type"] = attr.get("value")
        elif obj_relation == "threat-label":
            details["threat_label"] = attr.get("value")
        elif obj_relation == "url":
            for tag in attr.get("Tag"):
                if tag.get("name") == 'rsit:malicious-code="malware-distribution"':
                    details["classification"] = "malicious"
                elif tag.get("name") == 'sentinel-threattype:CryptoMining':
                    details["classification"] = "miner"
            
    logger.info("MISP data found")


def get_links(url, hash):
    """
    Get links to virustotal, urlhaus, etc. Returns list of links.
    
    url - the url
    hash - hash of the related file
    """

    links = []

    # get urlhaus link
    try:
        # Check, whether the URL is in the URLhaus database
        response = requests.post('https://urlhaus-api.abuse.ch/v1/url/', {'url' : url})
        # Parse the response from the API
        # (the expected result is a JSON with "query_status"="no_results" or "query_status"="ok" and other data items)
        json_response = response.json()
        if json_response['query_status'] == 'ok':
            links.append(json_response['urlhaus_reference'])
    except Exception as e:
        logger.error(f"Error getting URLHaus link for URL '{url}': ({type(e)}) {e}")

    # get virustotal hash link
    if hash:
        links.append(f"https://www.virustotal.com/gui/file/{hash.split(':')[1]}")
    
    return links
    
    

# Main conversion function
def convert_to_idea(rec, opts):
    """
    Get fields from UniRec message 'rec' and convert it into an IDEA message (Python dict()).

    rec - Record received on TRAP input interface (the report to convert).
          Its format satisfies what was defined by REQ_TYPE and REQ_FORMAT.
    opts - options parsed from command line (as returned by argparse.ArgumentParser)

    Return report in IDEA format (as Python dict). If None is returned, the alert is skipped.
    """
    time_now = getIDEAtime()
    url = "http://" + rec.HTTP_REQUEST_HOST.strip() + rec.HTTP_REQUEST_URL

    logger.info(f"Creating IDEA message for {rec.SRC_IP} -> {url}")

    details = {}

    if opts.misp_url and opts.misp_key:
        get_misp_info(url, opts.misp_url, opts.misp_key, details)
    
    if opts.evaluator_password:
        get_evaluator_info(url, details, opts.evaluator_password)

    # Number of packets and bytes - sum both directions if we have bidirectional flow, use just the one dir. otherwise
    packets = rec.PACKETS
    if "PACKETS_REV" in rec:
        packets += rec.PACKETS_REV
    bytes = rec.BYTES
    if "BYTES_REV" in rec:
        bytes += rec.BYTES_REV

    idea = {
        "Format": "IDEA0",
        "ID": getRandomId(),
        "EventTime": getIDEAtime(rec.TIME_FIRST),
        "DetectTime": time_now,
        "CreateTime": time_now,
        "Category": ["Intrusion.Botnet"],
        "Description": "Connection to an URL hosting a malware",
        "Note": create_msg(rec, details),
        "PacketCount": packets,
        "ByteCount": bytes,
        "Source": [
            {
                "Proto": ["http"]
            },
            {
                "URL": [url],
                "Type": ["Malware"],
                "Proto": ["http"],
                "Ref": [], 
            }
        ],
        "Node": [{
            "Name": "undefined",
            "SW": ["Nemea", "url_blacklist_filter"],
            "Type": [ "Flow", "Blacklist"]
        }],
        "Attach": [{}],
    }

    setAddr(idea["Source"][0], rec.SRC_IP)
    setAddr(idea["Source"][1], rec.DST_IP)

    if details.get("hash"):
        idea["Attach"][0]["Hash"] = [details["hash"]]

    if details.get("mime_type"):
        idea["Attach"][0]["ContentType"] = details["mime_type"]

    if details.get("content_size"):
        idea["Attach"][0]["Size"] = details["content_size"]
    
    if details.get("note"):
        idea["Source"][1]["Note"] = details["note"]

    ref_links = get_links(url, details.get("hash"))
    idea["Source"][1]["Ref"].extend(ref_links)

    if idea["Source"][1]["Ref"] == []:
        del idea["Source"][1]["Ref"]

    if idea["Attach"] == [{}]:
        del idea["Attach"]

    logger.info(f"Sending IDEA message:\n{json.dumps(idea, indent=4)}")

    return idea


# If conversion functionality needs to be parametrized, an ArgumentParser can be passed to Run function.
# These parameters are then parsed from command line and passed as "opts" parameter of the conversion function.
#parser = argparse.ArgumentParser()

# Run the module
if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("--misp-url", "-m", metavar="MISP-URL", required=True, type=str,
            help="URL of MISP instance. Required to get any information about URL. Connects to instance of MISP and gets additional information about malicious URL.")
    arg_parser.add_argument("--misp-key", "-k", metavar="MISP-API-KEY", required=True, type=str,
            help="API key for MISP instance. Required to get any information about URL.")
    arg_parser.add_argument("--evaluator-password", "-e", metavar="PASSWORD", type=str,
            help="Password for authentication to evaluator api. Optional to get more specific information about URL.")

    Run(
        module_name = MODULE_NAME,
        module_desc = MODULE_DESC,
        req_type = REQ_TYPE,
        req_format = REQ_FORMAT,
        conv_func = convert_to_idea,
        arg_parser = arg_parser
    )
