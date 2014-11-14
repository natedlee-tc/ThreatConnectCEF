ThreatConnectArcSight
=====================
This script will allow you to transform ThreatConnect indicators into the Common Event Format [(CEF)](https://protect724.hp.com/servlet/JiveServlet/previewBody/1072-102-6-4697/CommonEventFormat.pdf) used by HP's ArcSight product.  

The script uses the [ThreatConnect Python Client](https://github.com/Cyber-Squared-Inc/ThreatConnectPythonClient) to access a specified ThreatConnect instance for indicators, and produces indicators in CEF format via a syslogger.  Your ArcSight instance must be configured to ingest data from the syslogger specified in your arcsight.py file.

The script will produce CEF output, as in the example below (line breaks added for readability):
```
CEF:0|cybersquared|threatconnect|1|258349|N/A|5.0|confidence=11 dateAdded=2014-11-04T12:40:53-05:00 
lastModified=2014-11-04T12:40:53-05:00 summary=192.168.0.1 type=192.168.0.1 
weblink=https://app.threatconnect.com/auth/indicators/details/address.xhtml?address\=192.168.0.1
```

The code can be tailored to only pull certain indicators, or indicators meeting a certain threshold by changing the following line:

```
  # original line - gets all indicators for all owners in ownerList
  results = tc.get_indicators(owners=ownerList)
```

The ```tc.get_indicators()``` function can take a variety of inputs, see the ThreatConnect Python Client for additional uses:

```
  # gets all IP addresses for all owners in ownerList
  results = tc.get_indicators(indicator_type="addresses", owners=ownerList)      
  
  # gets all URL indicators with a confidence >=70
  tc.add_filter("confidence", ">=", 70):
  results = tc.get_indicators(indicator_type="urls", owners=ownerList)
  
  # gets all Host indicators tagged "APT"
  results = tc.get_indicators_by_tag("APT", indicator_type="hosts", owners=ownerList)
```

Severity in the CEF output is defined by the indicator's rating in ThreatConnect -- thsi can also be modified or weighted by the confidence if needed.
