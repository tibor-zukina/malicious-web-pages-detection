# Malicious web pages detection

This repository contains the code for detecting injected malicous HTML and JavaScript fragments in Web pages.

Page fetch functions usage (pagefetch.py module):

Raw HTML fetch from URL

websiteURL = 'https://example.com';

rawHTML = pagefetch.fetchRawHTML(websiteURL)

Fetching HTML from MongoDB database

connectionString = 'mongodb://user:password@host:port'

databaseName = 'webpage_database'

collectionName = 'webpage_collection'

pagefetch.setMongoConnection(connectionString, databaseName, collectionName)

webpageId = 'unique_website_id'

mongoHTML = pagefetch.fetchMongoHTML(webpageId)

Loading HTML from file

inputPath = 'input_html.html'

fileHTML = pagefetch.readHTMLFromFile(inputPath)

Saving HTML into file

outputPath = 'output_html.html'

pagefetch.writeHTMLToFile(outputPath, HTMLString)

Page attributes functions usage (pageattributes.py module):

Getting WHOIS information API info and completion status

pageattributes.setWhoisAPIKey('WHOIS-API-KEY');

whoisTestURL = 'http://example.com/'

whoisAPIData = pageattributes.whoisAPIInfo(whoisTestURL, 'json')

whoisStatus = pageattributes.whoisDataComplete(whoisTestURL);

Getting geolocation data from domain name or IP address

pageattributes.setGeoIPDatabasePath('directory-path/GeoLite2-Country.mmdb')

ipAddress = '1.1.1.1'

domainName = 'example.com'

ipAddressCountry = pageattributes.getCountryFromHost(ipAddress)

domainCountry = pageattributes.getCountryFromHost(domainName)

Getting JavaScript length

javaScriptCodeLength = pageattributes.getJavascriptCodeLength(HTMLString);

Getting obfuscated JavaScript length

obfuscatedJavaScriptCodeLength = pageattributes.getObfuscatedJavascriptCodeLength(HTMLString)

Dependendies:

Selenium for python: http://pypi.python.org/pypi/selenium

Selenium server: http://seleniumhq.org/download/

ChromeDriver for Chrome support: https://code.google.com/p/chromedriver/

Additional instructions:

https://github.com/lucianogiuseppe/JS-Auto-DeObfuscator

Testing if website supports HTTPS protokol

websiteURL = 'example.com'

httpsSupport = pageattributes.supportsHTTPS(websiteURL)

Getting website URL length

websiteURL = 'https://example.com'

urlLength = pageattributes.getURLLength(websiteURL)

Getting website TLD

websiteURL = 'example.com'

tld = pageattributes.getTLD(websiteURL)

Getting website Google Safe browsing status (malicious or benign)

pageattributes.setSafeBrowsingAPIKey('SAFE-BROWSING-API-KEY')

websiteURL = 'http://www.example.com/';

isMalicious = pageattributes.getSafeBrowsingStatus(websiteURL)
