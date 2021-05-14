import requests
import re
import json
import socket
from ipaddress import ip_address, IPv4Address
import geoip2.database
import http.client
from tld import get_tld
from pysafebrowsing import SafeBrowsing
import pagefetch
import jsado
import os
import urllib.request

whoisAPIKey = None
geoIPDatabasePath = None
geoIPDatabaseReader = None
whoisHost = 'pointsdb-bulk-whois-v1.p.rapidapi.com'
safeBrowsingAPIKey = None
safeBrowsingInstance = None

class WHOISAPIKeyNotSetException(Exception):
    pass
	
class GeoIPDatabasePathNotSetException(Exception):
    pass
	
class SafeBrowsingAPIKeyNotSetException(Exception):
    pass
	
def setWhoisAPIKey(APIKey):
    global whoisAPIKey
    whoisAPIKey = APIKey
	
def setGeoIPDatabasePath(databasePath):
    global geoIPDatabasePath, geoIPDatabaseReader
    geoIPDatabasePath = databasePath
    geoIPDatabaseReader = geoip2.database.Reader(geoIPDatabasePath)
	
def setSafeBrowsingAPIKey(APIKey):
    global safeBrowsingAPIKey, safeBrowsingInstance
    safeBrowsingAPIKey = APIKey
    safeBrowsingInstance = SafeBrowsing(safeBrowsingAPIKey)
	
def normalizeURL(originalURL):

    urlRegex = re.compile(r"https?://(www\.)?")
    url = urlRegex.sub('', originalURL).strip().strip('/')
    
    return url

def whoisAPIInfo(originalURL, format):

    if whoisAPIKey is None:
        raise WHOISAPIKeyNotSetException("WHOIS API key not set")
		
    url = normalizeURL(originalURL);
	
    whoisAPIEndpoint = "https://pointsdb-bulk-whois-v1.p.rapidapi.com/whois"

    querystring = {"domain":url, "format": format}

    headers = {
        'x-rapidapi-key': whoisAPIKey,
        'x-rapidapi-host': whoisHost
    }

    response = requests.request("GET", whoisAPIEndpoint, headers=headers, params=querystring)

    return json.loads(response.text)
	
def whoisDataComplete(url):

    whoisAPIData = whoisAPIInfo(url, 'json')
    if 'registrar_name' in whoisAPIData and whoisAPIData['registrar_name'] != '':
        who_is = 'complete'
    else:
        who_is = 'incomplete'

    return who_is;
	
def getIPFromDomain(domain):

    try: 
        ipAddress = socket.gethostbyname(domain) 
        return ipAddress 
    except: 
        print("Error getting IP address from domain name") 


def isValidIPAddress(ipToCheck):
    try:
        if isinstance(ip_address(ipToCheck), IPv4Address) or isinstance(ip_address(ipToCheck), IPv6Address):
   		    return True
    except ValueError:
        return False
		
def getCountryFromHost(host):

    if geoIPDatabasePath is None:
        raise GeoIPDatabasePathNotSetException("GeoIP database path not set")
		
    if(isValidIPAddress(host)):
	    ipAddress = host
    else:
	    ipAddress = getIPFromDomain(host)
    response = geoIPDatabaseReader.country(ipAddress)
    return response.country.name
	
def getJavascriptCodeLength(content):
    print(content)
    jsFragments=re.findall(r'<script>(.*?)</script>',content.replace("\n",""))
    jsCode=''.join(jsFragments)
    jsCodeLength = len(jsCode.encode('utf-8'))/1000
    return jsCodeLength
	
def listsDiff(li1, li2):
    return list(set(li1)-set(li2))
	
def getObfuscatedJavascriptCodeLength(content):
    pagefetch.writeHTMLToFile('obf.html', content);
    jsado.runDeobfuscation('obf.html', 'eval', 2000, False, False)
    os.remove('obf.html')
	
    print("Paste deobfuscated JavaScript code, type --END-- to finish")
    contents = []
    line = input()
    while (line != '---END---'):
        contents.append(line)
        line = input()
    deobfuscatedJs = ''.join(contents)
 
    os.remove('deobf.html')
    return len(deobfuscatedJs)/1000

def supportsHTTPS(originalURL):
    url = normalizeURL(originalURL)
    httpsEnabled= False
    try:
        conn = http.client.HTTPSConnection(url)
        conn.request("HEAD", "/")
        res = conn.getresponse()
        if res.status == 200 or res.status==301 or res.status==302:
            httpsEnabled= True   
    except Exception as msg:
        httpsEnabled = False
    finally:
        conn.close
        return httpsEnabled

def getTLD(url):
    websiteTLD = get_tld(str(url), fix_protocol=True)
    return websiteTLD

def getURLLength(url):
    return len(url)
	
def getSafeBrowsingStatus(url):
    if safeBrowsingAPIKey is None:
        raise SafeBrowsingAPIKeyNotSetException("Safe Browsing API key not set")
    try:
        result = safeBrowsingInstance.lookup_urls([url])
        label=result[url]['malicious']    
        return label
    except Exception as msg:
        label = ''
        return label
		
def checkForRedirect(inputData):
    if isinstance(inputData, int):
        responseCode = inputData
    elif isinstance(inputData, str):
        responseCode = urllib.request.urlopen(inputData).getcode()
    else:	
        responseCode = inputData['responseCode']
    if responseCode is not None and (responseCode == 301 or responseCode == 302):
        return True
    else:
        return False