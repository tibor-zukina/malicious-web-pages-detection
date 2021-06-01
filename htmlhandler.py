from html.parser import HTMLParser
from bs4 import BeautifulSoup
import urllib.parse
import re
from statistics import median, mean
import lexicutils

def makeBeautifulSoup(html):
    soup = BeautifulSoup(html, 'html.parser')
    return soup
	
def countScriptTags(soup):
    return len(soup.find_all('script'))
	
def countObjectTags(soup):
    return len(soup.find_all('object'))

def countIFrameTags(soup):
    return len(soup.find_all('iframe'))

def countEmbedTags(soup):
    return len(soup.find_all('embed'))
	
def countXMLProcessingInstructions(html):
    xmlInstructionSubstring = '<?xml-stylesheet';
    numberOfInstructions = html.count(xmlInstructionSubstring)
    return numberOfInstructions
	
def classifyScripts(soup, domain = None):
    scriptsByType = {'inline' : 0, 'internal' : 0, 'external' : 0}
    webpageScripts = soup.find_all('script');
    for script in webpageScripts:
        scriptSource = script.get('src')
        if scriptSource is None:
            scriptsByType['inline'] += 1
        else:
            scriptOnLocalPath = isPathLocal(scriptSource, domain)
            if scriptOnLocalPath:
                scriptsByType['internal'] += 1
            else:
                scriptsByType['external'] += 1
    return scriptsByType

def countInlineScripts(soup):
    scriptsByType = classifyScripts(soup)
    inlineScripts = scriptsByType['inline']
    return inlineScripts

def countInternalScripts(soup, domain = None):
    scriptsByType = classifyScripts(soup, domain)
    internalScripts	= scriptsByType['internal']
    return internalScripts
	
def countExternalScripts(soup, domain = None):
    scriptsByType = classifyScripts(soup, domain)
    externalScripts = scriptsByType['external']
    return externalScripts

def isPathLocal(scriptSource, domain = None):
    parsedUrl = urllib.parse.urlparse(scriptSource.replace('[','').replace(']',''))
    scriptDomain = parsedUrl.netloc
    if not scriptDomain or domain is not None and scriptDomain.replace('www.','') == domain.replace('www.',''):
        return True
    else:
        return False
		
def classifyCustomTags(soup, tag, domain = None):
    if tag == 'object':
        attribute = 'data'
    else:
        attribute = 'src'
    elementsByType = {'internal' : 0, 'external' : 0}
    webpageElements = soup.find_all(tag);
    for element in webpageElements:
        elementSource = element.get(attribute)
        if elementSource is not None:
            elementOnLocalPath = isPathLocal(elementSource, domain)
            if elementOnLocalPath:
                elementsByType['internal'] += 1
            else:
                elementsByType['external'] += 1
            
    return elementsByType
	
def countInternalObjects(soup, domain = None):
    objectsByType = classifyCustomTags(soup, 'object', domain)
    internalObjects	= objectsByType['internal']
    return internalObjects
	
def countExternalObjects(soup, domain = None):
    objectsByType = classifyCustomTags(soup, 'object', domain)
    externalObjects	= objectsByType['external']
    return externalObjects
	
def countInternalEmbeds(soup, domain = None):
    embedsByType = classifyCustomTags(soup, 'embed', domain)
    internalEmbeds	= embedsByType['internal']
    return internalEmbeds
	
def countExternalEmbeds(soup, domain = None):
    embedsByType = classifyCustomTags(soup, 'embed', domain)
    externalEmbeds	= embedsByType['external']
    return externalEmbeds
	
def countInternalIFrames(soup, domain = None):
    iFramesByType = classifyCustomTags(soup, 'iframe', domain)
    internalIFrames	= iFramesByType['internal']
    return internalIFrames
	
def countExternalIFrames(soup, domain = None):
    iFramesByType = classifyCustomTags(soup, 'iframe', domain)
    externalIFrames	= iFramesByType['external']
    return externalIFrames

iFramesWhitelist = ['www.googletagmanager.com']

def searchIFrames(soup):
    iFramesByType = {'small' : 0, 'large' : 0, 'total' : 0}
    webpageIFrames = soup.find_all('iframe');
    iFramesByType['total'] = len(webpageIFrames)
    for iFrame in webpageIFrames:
        width = iFrame.get('width')
        height = iFrame.get('height')
        iFrameSource = iFrame.get('src')
        if (width is not None):
            iFrameWidth = re.sub("[^0-9]", "", width)
        else:
            iFrameWidth = None
        if (height is not None):
            iFrameHeight = re.sub("[^0-9]", "", height)
        else:
            iFrameHeight = None
        if (iFrameWidth == '0' or iFrameHeight == '0') and (not isSourceWhitelisted(iFrameSource)):
            iFramesByType['small'] += 1
        else:
            iFramesByType['large'] += 1		
    return iFramesByType
	
def isSourceWhitelisted(iFrameSource):

    if iFrameSource is None:
        return False
    parsedUrl = urllib.parse.urlparse(iFrameSource.replace('[','').replace(']',''))
    iFrameDomain = parsedUrl.netloc
    if iFrameDomain in iFramesWhitelist:
        return True
    else:
        return False

def countTotalIFrames(soup):
    detectedIFrames = searchIFrames(soup)
    totalIFrames = detectedIFrames['total']
    return totalIFrames

def countSmallIFrames(soup):
    detectedIFrames = searchIFrames(soup)
    smallIFrames = detectedIFrames['small']
    return smallIFrames

def countLargeIFrames(soup):
    detectedIFrames = searchIFrames(soup)
    largeIFrames = detectedIFrames['large']
    return largeIFrames

scriptsWhitelist = ['document.getElementById(\'rs-plugin-settings-inline-css\')', 'document.getElementById("rs-plugin-settings-inline-css")']

def detectObfuscation(soup):
    scriptsByObfuscation = {'escaped_characters' : 0, 'unescape_function' : 0, 'obfuscated' : 0}
    webpageScripts = soup.find_all('script');
    for script in webpageScripts:
        escapedFound = False
        unescapeFound = False
        scriptText = ''.join(script.contents)
        if scriptText != '':
            if scriptText.find('unescape(') != -1:
                scriptsByObfuscation['unescape_function'] += 1
                escapedFound = True
            if re.search('%[0-9a-f]{2}',scriptText):
                scriptsByObfuscation['escaped_characters'] += 1
                unescapeFound = True
            if escapedFound and unescapeFound and (not isScriptWhitelisted(scriptText)):
                scriptsByObfuscation['obfuscated'] += 1
    return scriptsByObfuscation
	
def isScriptWhitelisted(scriptText):
    for listed in scriptsWhitelist:
       if scriptText.find(listed) != -1:
           return True
    return False

def countEscapedCharactersScripts(soup):
    detectedScripts = detectObfuscation(soup)
    escapedCharactersScripts = detectedScripts['escaped_characters']
    return escapedCharactersScripts

def countUnescapeFunctionScripts(soup):
    detectedScripts = detectObfuscation(soup)
    unescapeFunctionScripts = detectedScripts['unescape_function']
    return unescapeFunctionScripts

def countObfuscatedScripts(soup):
    detectedScripts = detectObfuscation(soup)
    obfuscatedScripts = detectedScripts['obfuscated']
    return obfuscatedScripts
	
def metaRedirectExists(soup, domain = None):
    metaTags = soup.find_all('meta')
    for meta in metaTags:
        httpEquiv = meta.get('http-equiv')
        content = meta.get('content')
        if (httpEquiv is not None and httpEquiv == 'refresh' and content is not None and (not isMetaRefreshContentWhitelisted(content, domain))):
            return True
    return False
	
def isMetaRefreshContentWhitelisted(content, domain):
    contentParts = content.split(';')
    urlPartFound = False
    acceptableTime = False
    minimumRedirectValue = 30
    for contentPart in contentParts:
        if contentPart.lower().startswith("url="):
            urlPartFound = True
            redirectUrl = contentPart.split("=")[1]
            parsedUrl = urllib.parse.urlparse(redirectUrl.replace('[','').replace(']',''))
            redirectDomain = parsedUrl.netloc
            if domain is not None and redirectDomain .replace('www.','') == domain.replace('www.',''):
                sameDomainRedirect = True
            else:
                sameDomainRedirect = False
        else:
            if (contentPart.isnumeric() and int(contentPart) >= minimumRedirectValue):
                acceptableTime = True
    if (not urlPartFound):
        sameDomainRedirect = True	
    return sameDomainRedirect and acceptableTime
	
def containsRedirectingScripts(soup):
    webpageScripts = soup.find_all('script');
    for script in webpageScripts:
        scriptText = ''.join(script.contents)
        if scriptText != '':
            textWithoutFunctions = re.sub('function[ \t]+[A-Za-z_][0-9A-Za-z_]+[ \t]*\([a-zA-Z0-9 _,]+\)[ \t]*{[^\}]*}',  '', scriptText.replace('\n',''))
            if re.search('window.location.href[ \t]*=|window.location.replace[ \t]*\(',textWithoutFunctions):
                return True			
    return False

def countRedirects(soup):
    redirects = 0
    metaTags = soup.find_all('meta')
    for meta in metaTags:
        httpEquiv = meta.get('http-equiv')
        content = meta.get('content')
        if (httpEquiv is not None and httpEquiv == 'refresh' and content is not None):
            redirects +=1
    webpageScripts = soup.find_all('script');
    for script in webpageScripts:
        scriptText = ''.join(script.contents)
        if scriptText != '':
            textWithoutFunctions = re.sub('function[ \t]+[A-Za-z_][0-9A-Za-z_]+[ \t]*\([a-zA-Z0-9 _,]+\)[ \t]*{[^\}]*}',  '', scriptText.replace('\n',''))
            redirectMatches = len(re.findall('window.location.href[ \t]*=|window.location.replace[ \t]*\(',textWithoutFunctions))
            redirects += redirectMatches	
    return redirects

def scriptsInjectXML(soup):
    webpageScripts = soup.find_all('script');
    for script in webpageScripts:
        scriptText = ''.join(script.contents)
        if scriptText != '':
            if ('document.implementation.createDocument' in scriptText) or ('XMLHttpRequest' in scriptText and 'responseXML' in scriptText) or ('DOMParser' in scriptText and 'text/xml' in scriptText):
                return True			
    return False
	
def getIFrameLinksStatistics(soup):
    iFrameLinkLengths = []
    iFrameLinkVowelRatios = []
    iFrameLinkSpecialCharRatios = []
    iFrameLinksStatistics = {}
    webpageIFrames = soup.find_all('iframe')
    for iFrame in webpageIFrames:
        iFrameSource = iFrame.get('src')
        if iFrameSource is not None:
            iFrameLinkLength = len(iFrameSource)
            iFrameLinkVowelRatio = lexicutils.vowelRatio(iFrameSource)
            iFrameLinkSpecialCharRatio = lexicutils.specialCharRatio(iFrameSource)
            iFrameLinkLengths.append(iFrameLinkLength)
            iFrameLinkVowelRatios.append(iFrameLinkVowelRatio)
            iFrameLinkSpecialCharRatios.append(iFrameLinkSpecialCharRatio)            			 
    iFrameLinksStatistics['medianLength'] = median(iFrameLinkLengths) if (len(iFrameLinkLengths) > 0) else 0
    iFrameLinksStatistics['minVowelRatio'] = min(iFrameLinkVowelRatios) if (len(iFrameLinkVowelRatios) > 0) else 0.00
    iFrameLinksStatistics['minSpecialCharRatio'] = min(iFrameLinkSpecialCharRatios) if (len(iFrameLinkSpecialCharRatios) > 0 )else 0.00
    return iFrameLinksStatistics
	
def getLinksStatistics(soup, domain = None):
    allLinks = []
    linkLengths = []
    externalLinksNumber = 0
    linksStatistics = {} 
    links = soup.find_all('a')
    for link in links:
        href = link.get('href')
        if(href is not None):
            allLinks.append(href)
    scripts = soup.find_all('script')
    for script in scripts:
        src = script.get('src')
        if(src is not None):
            allLinks.append(src)
    embeds = soup.find_all('embed')
    for embed in embeds:
        src = embed.get('src')
        if(src is not None):
            allLinks.append(src)
    objects = soup.find_all('object')
    for object in objects:
        data = object.get('data')
        if(data is not None):
            allLinks.append(data)
    styles = soup.find_all('style')
    for style in styles:
        rel = style.get('rel')
        if(rel is not None):
            allLinks.append(rel)
    linkDomains = []
    localDomainThreshold = 0.80
    for link in allLinks:
        linkDomain = urllib.parse.urlparse(link.replace('[','').replace(']','')).netloc
        if linkDomain:
            linkDomains.append(linkDomain)
    if domain is None:
        if len(linkDomains) > 0:
            mostCommonDomain = max(set(linkDomains), key=linkDomains.count)
            mostCommonDomainPercentage = (len([domain for domain in linkDomains if domain == mostCommonDomain]) / len(linkDomains))
            if mostCommonDomainPercentage >= localDomainThreshold:
                websiteDomain = mostCommonDomain
            else:
                websiteDomain = None
        else:
            websiteDomain = None
    else:
	    websiteDomain = domain
    for link in allLinks:		
        if (not isPathLocal(link,websiteDomain)):
            externalLinksNumber += 1
            linkLengths.append(len(link))
    linksStatistics['minLength'] = min(linkLengths) if (len(linkLengths) > 0) else 0
    linksStatistics['externalLinks'] = externalLinksNumber
    return linksStatistics

def getScriptStatistics(soup):
    linesNumbers = []
    wordsNumbers = []
    specialCharRatios = []
    scriptLengths = []
    minimumLineLengths = []
    maximumStringLengths = []
    minimumWordLengths = []
    minimumFunctionArgLengths = []
    scriptStatistics = {}
    scripts = soup.find_all('script')
    for script in scripts:
        scriptText = ''.join(script.contents)
        if scriptText != '':
            linesNumbers.append(lexicutils.linesNumber(scriptText))		
            wordsNumbers.append(lexicutils.wordsNumber(scriptText))
            specialCharRatios.append(lexicutils.specialCharRatio(scriptText))
            scriptLengths.append(len(scriptText))
            minimumLineLengths.append(lexicutils.minimumLineLength(scriptText))
            maximumStringLengths.append(lexicutils.maximumStringLength(scriptText))
            minimumWordLengths.append(lexicutils.minimumWordLength(scriptText))
            minimumFunctionArgLengths.append(lexicutils.minimumFunctionArgLength(scriptText))
    scriptStatistics['linesNumber'] = sum(linesNumbers) if (len(linesNumbers) > 0) else 0
    scriptStatistics['wordsNumber'] = sum(wordsNumbers) if (len(wordsNumbers) > 0) else 0
    scriptStatistics['specialCharRatio'] = mean(specialCharRatios) if (len(specialCharRatios) > 0) else 0.00
    scriptStatistics['minimumScriptLength'] = min(scriptLengths) if (len(scriptLengths) > 0) else 0
    scriptStatistics['minimumLineLength'] = min(minimumLineLengths) if(len(minimumLineLengths) > 0) else 0
    scriptStatistics['maximumStringLength'] = max(maximumStringLengths) if(len(maximumStringLengths) > 0) else 0
    scriptStatistics['minimumWordLength'] = min(minimumWordLengths) if(len(minimumWordLengths) > 0) else 0
    scriptStatistics['minimumFunctionArgLength'] = min(minimumFunctionArgLengths) if(len(minimumFunctionArgLengths) > 0) else 0
    return scriptStatistics;
	
def getObjectStatistics(soup):
    objectLinkLengths = []
    objectLinkVowelRatios = []
    objectLinkSpecialCharRatios = []
    objectAttributesNumbers = []
    objectStatistics = {}
    webpageObjects = soup.find_all('object')
    for object in webpageObjects:
        objectSource = object.get('data')
        if objectSource is not None:
            objectLinkLength = len(objectSource)
            objectLinkVowelRatio = lexicutils.vowelRatio(objectSource)
            objectLinkSpecialCharRatio = lexicutils.specialCharRatio(objectSource)
            objectLinkLengths.append(objectLinkLength)
            objectLinkVowelRatios.append(objectLinkVowelRatio)
            objectLinkSpecialCharRatios.append(objectLinkSpecialCharRatio)      
        objectAttributesNumber = countObjectAttributes(object)
        objectAttributesNumbers.append(objectAttributesNumber)
    objectStatistics['maxLinkLength'] = max(objectLinkLengths) if (len(objectLinkLengths) > 0) else 0
    objectStatistics['vowelRatio'] = mean(objectLinkVowelRatios) if (len(objectLinkVowelRatios) > 0) else 0.00
    objectStatistics['specialCharRatio'] = mean(objectLinkSpecialCharRatios) if (len(objectLinkSpecialCharRatios) > 0) else 0.00
    objectStatistics['medianAttributesNumber'] = median(objectAttributesNumbers) if (len(objectAttributesNumbers) > 0) else 0
    return objectStatistics
	
def countObjectAttributes(object):
    inlineAttributesCount = len(object.attrs.keys())
    paramsCount = len(object.find_all('param'))
    totalAttributes = inlineAttributesCount + paramsCount
    return totalAttributes
	
def extractJavaScriptCode(html):
    soup = makeBeautifulSoup(html)
    scripts = soup.find_all('script')
    scriptTexts = [] 
    for script in scripts:
        scriptText = ''.join(script.contents)
        if scriptText != '':
            scriptTexts.append(scriptText)
    return "\n".join(scriptTexts)			