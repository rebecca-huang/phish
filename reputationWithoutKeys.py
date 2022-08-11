import pip._vendor.requests
from pip._vendor import requests
import json
import time
# url encoding
import urllib.parse
from urllib.request import urlopen


def urlscanio(urlAddress):
    
    # fill API key here
    key = ''

    # grab info from API
    headers = {'API-Key': key,'Content-Type':'application/json'}
    data = {"url": urlAddress, "visibility": "public"}
    response = requests.post('https://urlscan.io/api/v1/scan/',headers=headers, data=json.dumps(data))
    # print(response)
    
    # link to results in json
    # resultLink = response.json()['api']

    # wait 10 seconds for results to load
    # print("loading...")
    time.sleep(10)

    # PRINTS LINK TO WEBPAGE WITH RESULTS; ALSO CONSIDER PRINTING THIS OUT print(response.json()['result'])
    # PRINTS LINK TO JSON RESULTS; CONSIDER PRINTING THIS OUT print(response.json()['api'])

    # json data of results
    resultJson = requests.get(response.json()['api'])
    # grab verdicts from results
    resultVerdict= resultJson.json()['verdicts']
    malicious = resultVerdict['overall']['malicious']
    print("urlscan.io -- Malicious: " + str(malicious)) 



# abuseIPDB API; takes in IP address, not URL
def abuseIPDB(ipAddress):

    # fill out key here
    key = ''

    # Defining the api-endpoint
    url = 'https://api.abuseipdb.com/api/v2/check'

    querystring = {
        'ipAddress': ipAddress,
        'maxAgeInDays': '90'
    }

    headers = {
        'Accept': 'application/json',
        'Key': key
    }

    response = requests.request(method='GET', url=url, headers=headers, params=querystring)

    # json results
    decodedResponse = json.loads(response.text)
    
    # print this if you want to see the full results 
    # print(response.text)

    # prints out abuseConfidenceScore
    print("AbuseIPDB -- Abuse Confidence Score (0-100): " + str(decodedResponse["data"]["abuseConfidenceScore"]))
    
    # formatted output -- print(json.dumps(decodedResponse, sort_keys=True, indent=4))

# bolsterAI, uses checkphishAPI key
def bolsterAI(urlAddress):

     # fill out key here
    key = ''

    headers = {
    }

    json_data = {
        'apiKey': key,
        'urlInfo': {
            'url': 'google.com',
        },
        'scanType': 'full',
    }

    response = requests.post('https://developers.checkphish.ai/api/neo/scan', headers=headers, json=json_data)

    # Note: json_data will not be serialized by requests
    # exactly as it was in the original request.
    #data = '{"apiKey": "59onse43icgm0fdrmptvzzx69y8dide2rclh1o1uphfyal7i72l9usv6elni0d72", "urlInfo": {"url": "google.com"}, "scanType": "full"}'
    #response = requests.post('https://developers.checkphish.ai/api/neo/scan', headers=headers, data=data)
    jobID = response.json()['jobID']

    # wait 10 seconds for results to load
    time.sleep(10)

    json_data = {
    'apiKey': '59onse43icgm0fdrmptvzzx69y8dide2rclh1o1uphfyal7i72l9usv6elni0d72',
    'jobID': jobID,
    'insights': True,
    }

    responseStatus = requests.post('https://developers.checkphish.ai/api/neo/scan/status', headers=headers, json=json_data)
    # consider printing this for full insights on webpage
    # print(responseStatus.json()['insights'])

    # prints out disposition(type)
    print("bolsterAI (checkPhishAI) -- Disposition: " + responseStatus.json()['disposition'])

    # prints out screen shot
    print("Screenshot of webpage: " + responseStatus.json()['screenshot_path']) 

  
def ipQualityScore(urlAddress):

     # fill out key here
    key = ''

    # url encoding
    encodedUrlAddress = urllib.parse.quote(urlAddress)


    link = "https://ipqualityscore.com/api/json/url/" + key + "/" + encodedUrlAddress

    # FIGURE OUT WAY TO PARSE DATA

    # store the response of URL
    response = urlopen(link)
            
    # storing the JSON response 
    # from url in data
    data_json = json.loads(response.read())
            
    # print the json response
    print("IP Quality Score -- Unsafe: " + str(data_json["unsafe"]) + ", Spamming: " + str(data_json["spamming"]) + 
        ", Malware: " + str(data_json["malware"]) + ", Phishing: " + str(data_json["phishing"]) + ", Suspicious: "
         + str(data_json["suspicious"]) + ", Adult: " + str(data_json["adult"]) + ", Risk score: " + 
         str(data_json["risk_score"]))


def pulsedive(urlAddress):

     # fill out key here
    key = ''

    headers = {
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
    }

    data = {
        'value': urlAddress,
        'probe': '0',
        'pretty': '1',
        'key': key,
    }   

    # get URL queried for scan
    response = requests.post('https://pulsedive.com/api/analyze.php', headers=headers, data=data)
    qid = response.json()['qid']

    # print qid for debugging
    # print(qid)

    headers = {
    }
    params = {
        "qid": qid,
        "pretty": "1",
        'key' : "efe153de3333aa57206c11e0e1237a296b7a543eb5264735dec5d86f1ad11f30"
    }

    # get results from scan using qid
    getResults = requests.get('https://pulsedive.com/api/analyze.php', headers=headers, params=params)
    # give time for results to load
    time.sleep(10)
    getResults = requests.get('https://pulsedive.com/api/analyze.php', headers=headers, params=params)
    status = getResults.json()
    print("PulseDive -- Risk: " + status["data"]["risk"])



   


def ibm(urlAddress):

     # fill out key here
    key = ''

    headers = {
        'accept': 'application/json',
        'Authorization': key,
    }

    response = requests.get('https://api.xforce.ibmcloud.com/api/url/google.com', headers=headers)

    print("IBM X-Force -- Score (1-10; Clean - Threat): " + str(response.json()["result"]["score"]))

def cyren(urlAddress):
    # fill out key here
    key = ''

    url = "https://api-url.cyren.com/api/v1/free/url"

    payload = json.dumps({
    "url": urlAddress
    })

    headers = {
    'Authorization': key,
    'Content-Type': 'application/json'
    }

    response = requests.request("POST", url, headers=headers, data=payload)

    print(response.text)

# takes in user input for a link
urlAddress = input("enter a URL to be scanned: ")
ipAddress = input("enter an IP Address to be scanned: ")

# call to urlScan.io
urlscanio(urlAddress)

# call to abuseIPDB, abuse confidence score (0-100), the higher the score, the higher confidence of a malicious website
abuseIPDB(ipAddress)

# call to bolsterAI
bolsterAI(urlAddress)

# call to pulsedive
pulsedive(urlAddress)

# call to ipQualityScore
ipQualityScore(urlAddress)

# call to IBM 
# ibm(urlAddress)

# call to Cyren
# cyren(urlAddress)

# further plan: bulk scanning
# catching errors 
# making verbose option





