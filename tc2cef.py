#####################################################
##      tc2cef.py
##      Updated 13 Nov 2014
##    
##      Polls ThreatConnect instance for indicators, 
##      and outputs to syslogger in CEF format.
##      
##      * Requires TC Python Client to be installed
##          * https://github.com/Cyber-Squared-Inc/ThreatConnectPythonClient.git
##          * Requires Requests Python library
##      
##      * Requires valid syslogger server (currently configured for localhost:514)
##
##      * Requires ArcSight to be configured to poll configured syslogger

from working_init import *
import logging
import logging.handlers

syslog_logger = logging.getLogger('syslog')
syslog_logger.setLevel(logging.DEBUG)
arcsight_handler = logging.handlers.SysLogHandler(address=('0.0.0.0', 514))
syslog_logger.addHandler(arcsight_handler)


def cef_format_prefix(unformatted):
    formatted = unformatted.replace('|', '\|').replace('"\"', '\\')
    return formatted

def cef_format_extension(unformatted):
    formatted = unformatted.replace('"\"', '\\').replace('=', '\=')
    return formatted

def main():
    """
    Make a request to grab address indicators from a particular community.
    """

    # This will look for *ALL* Indicators in ThreatConnect; can change/filter as needed
    ownerList=['Your Org Here', 'Example Community']
    results = tc.get_indicators(owners=ownerList) 
    
    if results.status() == "Success":
        results_data = results.data()

        for result in results_data._data:
            cef = (indicatorToCEF(result)).replace("\r\n", "\n").encode('utf-8', "ignore")
            print (cef)
            # uncomment line below for syslog output
            # syslog_logger.critical(cef)
          


def indicatorToCEF(event):
    #
    # CEF Prefix
    #

    # Version - integer
    cef_version = "0"

    # Vendor - string
    cef_device_vendor = cef_format_prefix("cybersquared")

    # Product - string
    cef_device_product = cef_format_prefix("threatconnect")

    # Product Version - integer
    cef_product_version = "1"

    # CEF Signature (id) - string (in this case id is integer) 
    # The signature should map to CVE or other common signature id for better correlation
    cef_signature_id = event['id']

    # Severity - integer
    # The value should be integer 1-10 with 10 be highest.
    # If threatconnect only goes up to 5 some modifications might be a good idea.
    # This could be an algorithm between rating and confidence
    if "rating" in event:
        cef_severity = event['rating']
    else:
        cef_severity = 0

    # CEF Name (description) - string 
    if "description" in event:
        cef_name = event['description']
    else:
        cef_name = "N/A"

    #
    # CEF Extension
    #
    cef_extension = ""

    # Confidence - integer
    if "confidence" in event:
        cef_extension += "confidence=%s " % event['confidence']

    # DateAdded - string
    if "dateAdded" in event:
        cef_extension += "dateAdded=%s " % cef_format_extension(event['dateAdded'])

    # Description - string
    if "description" in event:
        cef_extension += "description=%s " % cef_format_extension(event['description'])

    # lastModified - string
    if "lastModified" in event:
        cef_extension += "lastModified=%s " % cef_format_extension(event['lastModified'])

    # NameownerName - string
    if "NameownerName" in event:
        cef_extension += "NameownerName=%s " % cef_format_extension(event['NameownerName'])

    # Summary - string
    if "summary" in event:
        cef_extension += "summary=%s " % cef_format_extension(event['summary'])

    # Type - string
    if "type" in event:
        cef_extension += "type=%s " % cef_format_extension(event['summary'])

    # WebLink - string
    if "webLink" in event:
        cef_extension += "weblink=%s" % cef_format_extension(event['webLink'])

    # Build CEF String
    CEF = "CEF:%s|%s|%s|%s|%s|%s|%s|%s" % \
        (cef_version,cef_device_vendor,cef_device_product,cef_product_version,\
         cef_signature_id,cef_name,cef_severity,cef_extension)

    return CEF

if __name__ == "__main__":
    main()


"""
CEF Guidelines

CEF must be UTF-8 encoded
"|" in prefix must be escaped "\|", but not in Extension field
"\" in prefix or extension must be escaped "\\"
"=" in prefix or extension must be escaped "\="

syslog
<date> host messsage

CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension

Version -> integer
Device Vendor -> string (unique to cybersquared)
Device Product -> string (unique to cybersquared product line)
Device Version -> string (unique to cybersquared product line version)
Signature ID -> string (unique identifier of event like CVE)
Name -> sting (human readable description of event)
Severity -> integer (0-10 with 10 being the most important)
Extension -> key/value pairs (from Extension dictionary sperated by quotes)


Example syslog:
Sep 19 08:26:10 host CEF:0|security|threatmanager|1.0|100|worm 
successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232

Custom Extension Naming Guidelines 

Custom extension keys should take the following form 
  VendornameProductnameExplanatoryKeyName 

"""
