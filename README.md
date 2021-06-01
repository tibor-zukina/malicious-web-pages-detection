# Malicious web pages detection

This repository contains the code for detecting injected malicous HTML and JavaScript fragments in Web pages.

Page fetch functions usage (pagefetch.py module):
---


Raw HTML fetch from URL:
---

websiteURL = 'https://example.com';

rawHTML = pagefetch.fetchRawHTML(websiteURL)


Fetching list of HTML pages from URL list:
---

websiteURLList = ['https://example.net', 'https://example.net']

rawHTMLList = pageFetch.fetchRawHTMLList(websiteURLList)

Fetching HTML from MongoDB database:
---

connectionString = 'mongodb://user:password@host:port'

databaseName = 'webpage_database'

collectionName = 'webpage_collection'

pagefetch.setMongoConnection(connectionString, databaseName, collectionName)

webpageId = 'unique_website_id'

mongoHTML = pagefetch.fetchMongoHTML(webpageId)


Fetching list of HTML pages from MongoDB database:
---


connectionString = 'mongodb://user:password@host:port'

databaseName = 'webpage_database'

collectionName = 'webpage_collection'

pagefetch.setMongoConnection(connectionString, databaseName, collectionName)

webpageIdList = ['unique_website_id_1', 'unique_website_id_2']

mongoHTMLList = pagefetch.fetchMongoHTMLList(webpageIdList)


Fetching set of HTML pages from MongoDB database:
---

connectionString = 'mongodb://user:password@host:port'

databaseName = 'webpage_database'

collectionName = 'webpage_collection'

pagefetch.setMongoConnection(connectionString, databaseName, collectionName)

mongoHTMLSet = pagefetch.fetchMongoHTMLSet(100)


Loading HTML from file:
---

inputPath = 'input_html.html'

fileHTML = pagefetch.readHTMLFromFile(inputPath)


Loading list of HTML files from directory:
---

inputPath = 'html_files'

directoryHTMLList = pagefetch.readHTMLListFromDir(inputPath)


Loading list of HTML files from database pages directory:
---

inputPath = 'database_webpages'

databaseDirectoryHTMLList = pagefetch.readHTMLListFromDatabaseDir(inputPath)


Saving HTML into file:
---

outputPath = 'output_html.html'

pagefetch.writeHTMLToFile(outputPath, HTMLString)


Page attributes functions usage (pageattributes.py module):
---


Getting WHOIS information API info and completion status:
---

pageattributes.setWhoisAPIKey('WHOIS-API-KEY');

whoisTestURL = 'http://example.com/'

whoisAPIData = pageattributes.whoisAPIInfo(whoisTestURL, 'json')

whoisStatus = pageattributes.whoisDataComplete(whoisTestURL)


Getting geolocation data from domain name or IP address:
---

pageattributes.setGeoIPDatabasePath('directory-path/GeoLite2-Country.mmdb')

ipAddress = '1.1.1.1'

domainName = 'example.com'

ipAddressCountry = pageattributes.getCountryFromHost(ipAddress)

domainCountry = pageattributes.getCountryFromHost(domainName)


Getting JavaScript code length:
---

javaScriptCodeLength = pageattributes.getJavascriptCodeLength(HTMLString);


Getting obfuscated JavaScript code length:
---

obfuscatedJavaScriptCodeLength = pageattributes.getObfuscatedJavascriptCodeLength(HTMLString)

Dependendies:

Selenium for python: http://pypi.python.org/pypi/selenium

Selenium server: http://seleniumhq.org/download/

ChromeDriver for Chrome support: https://code.google.com/p/chromedriver/

Additional instructions:

https://github.com/lucianogiuseppe/JS-Auto-DeObfuscator


Testing if website supports HTTPS protokol:
---

websiteURL = 'example.com'

httpsSupport = pageattributes.supportsHTTPS(websiteURL)


Getting website URL length:
---

websiteURL = 'https://example.com'

urlLength = pageattributes.getURLLength(websiteURL)


Getting website TLD:
---

websiteURL = 'example.com'

tld = pageattributes.getTLD(websiteURL)


Getting website Google Safe browsing status (malicious or benign):
---

pageattributes.setSafeBrowsingAPIKey('SAFE-BROWSING-API-KEY')

websiteURL = 'http://www.example.com/'

isMalicious = pageattributes.getSafeBrowsingStatus(websiteURL)


Finding redirects in HTTP response code:
---

websiteURL = 'http://www.example.com/'

isRedirecting = checkForRedirect(websiteURL)


HTML handler functions usage (htmlhandler.py module):
---


Generating BeautifulSoup object:
---

testPath = 'test/test-html.html'

testHTML = pagefetch.readHTMLFromFile(testPath)

testSoupObject = htmlhandler.makeBeautifulSoup(testHTML)


Counting HTML tags:
---

testPath = 'test/simple-html.html'

testHTML = pagefetch.readHTMLFromFile(testPath)

testSoupObject = htmlhandler.makeBeautifulSoup(testHTML)

numberOfScriptTags = htmlhandler.countScriptTags(testSoupObject)

numberOfObjectTags = htmlhandler.countObjectTags(testSoupObject)

numberOfIFrameTags = htmlhandler.countIFrameTags(testSoupObject)

numberOfEmbedTags = htmlhandler.countEmbedTags(testSoupObject)

numberOfXMLInstructions = htmlhandler.countXMLProcessingInstructions(testHTML)


Clasiffication of scripts (inline, internal, external):
---

testPath = 'test/scripts-html.html'

testHTML = pagefetch.readHTMLFromFile(testPath)

testSoupObject = htmlhandler.makeBeautifulSoup(testHTML)

inlineScripts = htmlhandler.countInlineScripts(testSoupObject)

internalScripts = htmlhandler.countInternalScripts(testSoupObject)

externalScripts = htmlhandler.countExternalScripts(testSoupObject)


Classification of other HTML elements (internal, external):
---

testPath = 'test/elements-html.html'

testHTML = pagefetch.readHTMLFromFile(testPath)

testSoupObject = htmlhandler.makeBeautifulSoup(testHTML)

internalObjects = htmlhandler.countInternalObjects(testSoupObject, 'example.com')

externalObjects = htmlhandler.countExternalObjects(testSoupObject, 'example.com')

internalEmbeds = htmlhandler.countInternalEmbeds(testSoupObject, 'example.com')

externalEmbeds = htmlhandler.countExternalEmbeds(testSoupObject, 'example.com')

internalIFrames = htmlhandler.countInternalIFrames(testSoupObject, 'example.com')

externalIFrames = htmlhandler.countExternalIFrames(testSoupObject, 'example.com')


Classification of iframes by size (total, large, small):
---

testPath = 'test/iframes-html.html'

testHTML = pagefetch.readHTMLFromFile(testPath)

testSoupObject = htmlhandler.makeBeautifulSoup(testHTML)

totalIFrames = htmlhandler.countTotalIFrames(testSoupObject)

smallIFrames = htmlhandler.countSmallIFrames(testSoupObject)

largeIFrames = htmlhandler.countLargeIFrames(testSoupObject)


Finding obfuscation in scripts:
---

testPath = 'test/obfuscated-html.html'

testHTML = pagefetch.readHTMLFromFile(testPath)

testSoupObject = htmlhandler.makeBeautifulSoup(testHTML)

escapedCharactersScripts = htmlhandler.countEscapedCharactersScripts(testSoupObject)

unescapeFunctionScripts = htmlhandler.countUnescapeFunctionScripts(testSoupObject)

obfuscatedScripts = htmlhandler.countObfuscatedScripts(testSoupObject)


Detect HTTP redirections:
---

testPath = 'test/redirection-html.html'

testHTML = pagefetch.readHTMLFromFile(testPath)

testSoupObject = htmlhandler.makeBeautifulSoup(testHTML)

containsMetaRedirect = htmlhandler.metaRefreshTagsExist(testSoupObject)

containsScriptRedirects = htmlhandler.containsRedirectingScripts(testSoupObject)


Detect XML injection in JavaScript:
---

testPath = 'test/xml-inject-html.html'

testHTML = pagefetch.readHTMLFromFile(testPath)

testSoupObject = htmlhandler.makeBeautifulSoup(testHTML)

doScriptsInjectHTML = htmlhandler.scriptsInjectXML(testSoupObject)


Lexic functions usage (lexicutils.py module):
---


Calculation vowel ratio in a string:
---

lexicutils.vowelRatio(str)


Calculating special characters ration in a string:
---

lexicutils.specialCharRation(str)


Calculating lines number in a multiline string:
---

lexicutils.linesNumber(str)


Calculating words number in a string:
---

lexicutils.wordsNumber(str)


Calculating minimum line length in a multiline string:
---

lexicutils.minimumLineLength(str)


Calculating max string literals length in a JavaScript string:
---

lexicutils.maximumStringLength(javascriptStr)


Calculating minimum word length in a string:
---

lexicutils.minimumWordLength(str)


Calculating minimum function argument length in a JavaScript string:
---

lexicutils.minimumFunctionArgLength(javascriptStr)


Scoring checking functions usage (scoringchecker.py module):
---


Set scoring parameters object:
---

scoringParametersPath = 'scoring_parameters.json'

scoringchecker.setScoringParameters(scoringParametersPath)


Preparing scoring parameters for webpages set:
---

inputPath = 'database_webpages'

scoringParametersPath = 'scoring_parameters.json' 

mongoHTMLSet = pagefetch.readHTMLListFromDatabaseDir(inputPath)

scoringchecker.prepareScoringParameters(mongoHTMLSet, scoringParametersPath) 


Calculating scores for HTML page:
---

scoringParametersPath = 'scoring_parameters.json' 

htmlPath = 'test_html.html'

html = pagefetch.readHTMLFromFile(htmlPath)

scoringchecker.calculateScores(html)


Generate malicious diagonisis for given score:
---

scoringParametersPath = 'scoring_parameters.json' 

htmlPath = 'test_html.html'

html = pagefetch.readHTMLFromFile(htmlPath)

scores = scoringchecker.calculateScores(html)

scoringchecker.generateMaliciousExplanations(scores)


Yara checking functions usage (yarachecker.py module):
---



Generate yara rules object:
---

yaraRulesPatch = 'yara_rules.yar'

yarachecker.setYaraRulesObject('yara_rules.yar')


Get yara rules matches:
---

yaraRulesPath = 'yara_rules.yar'

htmlPath = 'test_html.html'

yarachecker.setYaraRulesObject(yaraRulesPath)

html = pagefetch.readHTMLFromFile(htmlPath)

matches = yarachecker.getYaraMatches(html)


Website checking functions usage (pagechecker.py module):
---


Check HTML by the selected algorithm:
---

testPath = 'test/test-html.html'

scoringParametersPath = 'scoring_parameters.json'

yaraRulesPath = 'yara_rules.yar'

testHTML = pagefetch.readHTMLFromFile(testPath)

staticHeuristicsCheckResult = pagechecker.analyzeWebpage({'html': testHTML}, 'static heuristics')

scoringMechanismCheckResult = pagechecker.analyzeWebpage({'html': testHTML}, 'scoring mechanism' , scoringParametersPath)

yaraRulesCheckResult = pagechecker.analyzeWebpage({'html': testHTML}, 'yara rules', yaraRulesPath)


Check HTML list by selected algorithm:
---

inputPath = 'database_webpages'

scoringParametersPath = 'scoring_parameters.json'

yaraRulesPath = 'yara_rules.yar'

mongoHTMLSet = pagefetch.readHTMLListFromDatabaseDir(inputPath)

staticHeuristicsCheckResult = pagechecker.checkWebpages(mongoHTMLSet, 'static heuristics')

scoringMechanismCheckResult = pagechecker.checkWebpages(mongoHTMLSet, 'scoring mechanism', scoringParametersPath = scoringParametersPath)

yaraRulesCheckResult = pagechecker.checkWebpages(mongoHTMLSet, 'yara rules', yaraRulesPath = yaraRulesPath)

randomAlgorithmsCheckResult = pagechecker.checkWebpages(mongoHTMLSet, 'random', yaraRulesPath = yaraRulesPath)

allAlgorithmsCheckResult = pagechecker.checkWebpages(mongoHTMLSet, 'all', yaraRulesPath = yaraRulesPath)


Testing malicious webpages detection algorithms (test.py module):
---


Testing algorithm on set of webpages:
---

connectionString = open('connection_string', 'r').readline()

databaseName = 'websecradar'

collectionName = 'crawled_data_pages_v0'

staticHeuristicsDatabaseTest(connectionString, databaseName, collectionName, 10)   

scoringMechanismDatabaseTest(connectionString, databaseName, collectionName, 10, scoringParametersPath = 'scoring_parameters.json')

yaraRulesDatabaseTest(connectionString, databaseName, collectionName, 10, yaraRulesPath = 'yara_rules.yar')


Testing algorithm on set of webpages with expected results:
---

connectionString = open('connection_string', 'r').readline()

databaseName = 'websecradar'

collectionName = 'crawled_data_pages_v0'

staticHeuristicsDatabaseTest(connectionString, databaseName, collectionName, 10, expectedResultsPath = 'test/expected_results.csv')   

scoringMechanismDatabaseTest(connectionString, databaseName, collectionName, 10, scoringParametersPath = 'scoring_parameters.json', expectedResultsPath = 'test/expected_results.csv')

yaraRulesDatabaseTest(connectionString, databaseName, collectionName, 10, yaraRulesPath = 'yara_rules.yar', expectedResultsPath = 'test/expected_results.csv')


Comparing different algorithms results:
---

databaseDirectoryPath = 'database_webpages'

compareAlgorithms(databaseDirectoryPath, 'static heuristics', 'scoring mechanism', scoringParametersPath = 'scoring_parameters.json')

compareAlgorithms(databaseDirectoryPath, 'static heuristics', 'yara rules', yaraRulesPath = 'yara_rules.yar')

compareAlgorithms(databaseDirectoryPath, 'scoring mechanism', 'yara rules', scoringParametersPath = 'scoring_parameters.json', yaraRulesPath = 'yara_rules.yar')


Analysing all algorithms:
---

databaseDirectoryPath = 'database_webpages'

analyzeAllAlgorithms(databaseDirectoryPath, scoringParametersPath = 'scoring_parameters.json', yaraRulesPath = 'yara_rules.yar', analysisResultsPath = 'test/analysis_results.csv')

