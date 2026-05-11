# main.py
# this script takes threat data and sends it to MISP
# it also tags each threat with how relevant it is to our org
# based on what software/assets the org actually uses

from pymisp import PyMISP
import urllib3
import json

# stops SSL warnings from spamming the terminal
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# MISP login details
MISP_URL = ""
MISP_KEY = ""

misp = PyMISP(MISP_URL, MISP_KEY, ssl=False)
print("connected to MISP")

# load the org profile from a json file the client provides
with open("org_profile.json") as f:
    org = json.load(f)

# pull out useful words from the org profile to match against
# we grab OS names, CPE product names, and asset names
terms = []

for cpe in org.get("cpe_list", []):
    parts = cpe.split(":")
    if len(parts) > 5:
        terms.append(parts[3].replace("_", " "))   # vendor e.g. "microsoft"
        terms.append(parts[4].replace("_", " "))   # product e.g. "windows 11"

for os in org["technology_stack"]["endpoint"]["os_workstation"]:
    terms.append(os.lower())

for os in org["technology_stack"]["endpoint"]["os_server"]:
    terms.append(os.lower())

for asset in org["asset_exposure"]["critical_assets"]:
    for word in asset["name"].lower().split():
        terms.append(word)

# remove duplicates and short words
terms = list(set([t.lower() for t in terms if len(t) >= 3]))
print("org terms loaded:", terms)

# get the org severity threshold - how picky they are about alerts
threshold = org["risk_profile"]["severity_threshold"]
print("severity threshold:", threshold)

# load threat feed from file, use test data if file not found
try:
    with open("feed.json") as f:
        feed = json.load(f)
    print("loaded feed.json")
except FileNotFoundError:
    print("feed.json not found, using test data")
    feed = [
        {"type": "domain",  "value": "bad1.com",            "confidence": 80},
        {"type": "domain",  "value": "evil.net",            "confidence": 60},
        {"type": "ip-dst",  "value": "203.0.113.42",        "confidence": 30},
        {"type": "domain",  "value": "windows-exploit.com", "confidence": 40},
        {"type": "domain",  "value": "virtualbox-pwn.net",  "confidence": 35},
        {"type": "domain",  "value": "ubuntu-rootkit.com",  "confidence": 45},
    ]

# figure out the relevance tag for each indicator
# if the indicator mentions something from our org profile, boost the confidence
def get_tag(value, confidence):
    matches = [t for t in terms if t in value.lower()]

    if matches:
        confidence = min(confidence + 20, 100)
        print("  matched:", matches, "-> boosted confidence to", confidence)

    if confidence >= 75:
        return "relevance:high"
    elif confidence >= 50:
        return "relevance:medium"
    else:
        return "relevance:low"

# create one event in MISP to hold all the indicators
event = misp.add_event({
    "info": "Curated Threat Feed - " + org["organisation"]["name"],
    "distribution": 0,
    "threat_level_id": 2,
    "analysis": 1,
    "tag": "feed:curated"
})

event_id = event["Event"]["id"]
print("created event:", event_id)

# loop through each indicator, add it to the event and tag it
for item in feed:

    attr = misp.add_attribute(event_id, {
        "type": item["type"],
        "value": item["value"],
        "to_ids": True,
        "comment": "confidence: " + str(item["confidence"]) + "%"
    })

    attr_uuid = attr["Attribute"]["uuid"]
    tag = get_tag(item["value"], item["confidence"])

    misp.tag(attr_uuid, "source:curated")
    misp.tag(attr_uuid, tag)

    print("added:", item["value"], "->", tag)

# publish so it shows up in the dashboard
misp.publish(event_id)
print("event published!")

# read it back to check tags saved correctly
print("\n--- verification ---")
check = misp.get_event(event_id)
for attr in check["Event"]["Attribute"]:
    tags = [t["name"] for t in attr.get("Tag", [])]
    print(attr["value"], "|", tags)

# This is purely a test environment at this point
# All feed inputs are currently fixed to lines in code
# To change for real use, remove the 'feed' section from line 59 add the following code:

#with open("feed.txt") as f:
#    feed = []
#    for line in f:
#        parts = line.strip().split(",")
#        feed.append({
#            "type":       parts[0],
#            "value":      parts[1],
#            "confidence": int(parts[2])
#        })
#print("loaded feed.txt")