from html.parser import HTMLParser
from bs4 import BeautifulSoup
import urllib.parse
import re

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
    parsedUrl = urllib.parse.urlparse(scriptSource)
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

def searchIFrames(soup):
    iFramesByType = {'small' : 0, 'large' : 0, 'total' : 0}
    webpageIFrames = soup.find_all('iframe');
    iFramesByType['total'] = len(webpageIFrames)
    for iFrame in webpageIFrames:
        iFrameWidth = re.sub("[^0-9]", "", iFrame.get('width'))
        iFrameHeight = re.sub("[^0-9]", "", iFrame.get('height'))
        if iFrameWidth == '0' or iFrameHeight == '0':
            iFramesByType['small'] += 1
        else:
            iFramesByType['large'] += 1		
    return iFramesByType

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
            if escapedFound and unescapeFound:
                scriptsByObfuscation['obfuscated'] += 1
    return scriptsByObfuscation

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
	
def metaRefreshTagsExist(soup):
    metaTags = soup.find_all('meta')
    for meta in metaTags:
        httpEquiv = meta.get('http-equiv')
        content = meta.get('content')
        if (httpEquiv is not None and httpEquiv == 'refresh' and content is not None):
            return True
    return False

def containsRedirectingScripts(soup):
    webpageScripts = soup.find_all('script');
    for script in webpageScripts:
        scriptText = ''.join(script.contents)
        if scriptText != '':
            textWithoutFunctions = re.sub('function[ \t]+[A-Za-z_][0-9A-Za-z_]+[ \t]*\(.*\)[ \t]*{ .*}',  '', scriptText.replace('\n',''))
            if re.search('window.location.href[ \t]*=|window.location.replace[ \t]*\(',textWithoutFunctions):
                return True			
    return False