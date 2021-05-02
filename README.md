# Malicious web pages detection

This repository contains the code for detecting injected malicous HTML and JavaScript fragments in Web pages.

# Page fetch functions usage (pagefetch.py module):

# raw HTML fetch from URL

websiteURL = 'https://example.com';

rawHTML = pagefetch.fetchRawHTML(websiteURL)

# fetching HTML from MongoDB database

connectionString = 'mongodb://user:password@host:port'

databaseName = 'webpage_database'

collectionName = 'webpage_collection'

pagefetch.setMongoConnection(connectionString, databaseName, collectionName)

webpageId = 'unique_website_id'

mongoHTML = pagefetch.fetchMongoHTML(webpageId)

# loading HTML from file

inputPath = 'input_html.html'

fileHTML = pagefetch.readHTMLFromFile(inputPath)

# saving HTML into file

outputPath = 'output_html.html'

pagefetch.writeHTMLToFile(outputPath, HTMLString)

# Page attributes functions usage (pageattributes.py module):

# getting WHOIS information API info and completion status

pageattributes.setWhoisAPIKey('WHOIS-API-KEY');

whoisTestURL = 'http://example.com/'

whoisAPIData = pageattributes.whoisAPIInfo(whoisTestURL, 'json')

whoisStatus = pageattributes.whoisDataComplete(whoisTestURL);

# getting geolocation data from domain name or IP address

pageattributes.setGeoIPDatabasePath('directory-path/GeoLite2-Country.mmdb')

ipAddress = '1.1.1.1'

domainName = 'example.com'

ipAddressCountry = pageattributes.getCountryFromHost(ipAddress)

domainCountry = pageattributes.getCountryFromHost(domainName)

# getting JavaScript length

javaScriptCodeLength = pageattributes.getJavascriptCodeLength(HTMLString);

# getting obfuscated JavaScript length

obfuscatedJavaScriptCodeLength = pageattributes.getObfuscatedJavascriptCodeLength(HTMLString)

Dependendies:

Selenium for python: http://pypi.python.org/pypi/selenium

Selenium server: http://seleniumhq.org/download/

ChromeDriver for Chrome support: https://code.google.com/p/chromedriver/

Additional instructions:

https://github.com/lucianogiuseppe/JS-Auto-DeObfuscator

# testing if website supports HTTPS protokol

websiteURL = 'example.com'

httpsSupport = pageattributes.supportsHTTPS(websiteURL)

# getting website URL length

websiteURL = 'https://example.com'

urlLength = pageattributes.getURLLength(websiteURL)

# getting website TLD

websiteURL = 'example.com'

tld = pageattributes.getTLD(websiteURL)

# getting website Google Safe browsing status (malicious or benign)

pageattributes.setSafeBrowsingAPIKey('SAFE-BROWSING-API-KEY')

websiteURL = 'http://www.example.com/';

isMalicious = pageattributes.getSafeBrowsingStatus(websiteURL)
