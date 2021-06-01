import pageattributes
import htmlhandler
import random
import yarachecker
import scoringchecker
from yarachecker import rulesInterpretation

supportedAlgorithms = ('static heuristics', 'scoring mechanism', 'yara rules')

class UnsupportedCheckingAlgorithmException(Exception):
    pass
	
class YaraRulesPathNotSetException(Exception):
    pass

def checkByStaticHeuristics(html, domain = None, httpResponseCode = None):
    analysisResults = {'status':'not classified', 'details':''}
    bsObject = htmlhandler.makeBeautifulSoup(html)
    iFramesData = htmlhandler.searchIFrames(bsObject)
    totalIFrames = iFramesData['total']	
    if totalIFrames > 0:
        smallIFrames = iFramesData['small']
        if smallIFrames > 0:
            analysisResults['status'] = 'malicious'
            analysisResults['details'] = 'webpage contains small iframe elements'
        else:
            objectsNumber = htmlhandler.countObjectTags(bsObject)
            if objectsNumber > 0:
                analysisResults['status'] = 'malicious'
                analysisResults['details'] = 'webpage contains iframe elements and object elements'
            else:
                embedNumber = htmlhandler.countEmbedTags(bsObject)
                if embedNumber > 0:
                    analysisResults['status'] = 'malicious'
                    analysisResults['details'] = 'webpage contains iframe elements and embed elements'
                else:
                    scriptsNumber = htmlhandler.countScriptTags(bsObject)
                    if scriptsNumber > 4:
                        analysisResults['status'] = 'benign'
                        analysisResults['details'] = 'no malicious properties detected'
                    else:
                        if scriptsNumber <= 2:
                            containsMetaRedirects = htmlhandler.metaRefreshTagsExist(bsObject)
                            containsScriptRedirects = htmlhandler.containsRedirectingScripts(bsObject)
                            if containsMetaRedirects or containsScriptRedirects:
                                analysisResults['status'] = 'malicious'
                                analysisResults['details'] = 'webpage contains iframe elements with small number of script tags and redirects'
                            else:
                                analysisResults['status'] = 'benign'
                                analysisResults['details'] = 'no malicious properties detected'
                        else:
                            analysisResults['status'] = 'benign'
                            analysisResults['details'] = 'no malicious properties detected'
						
    else:
        obfuscationData = htmlhandler.detectObfuscation(bsObject)
        scriptsWithEscapedCharacters = obfuscationData['escaped_characters']
        if scriptsWithEscapedCharacters > 0:
            obfuscatedScripts = obfuscationData['obfuscated']
            if obfuscatedScripts > 0:
                analysisResults['status'] = 'malicious'
                analysisResults['details'] = 'obfuscated javascript code has been detected'
            else:
                analysisResults['status'] = 'benign'
                analysisResults['details'] = 'no malicious properties detected'	
        else:
            xmlProcessingInstructionsNumber = htmlhandler.countXMLProcessingInstructions(html)
            if xmlProcessingInstructionsNumber > 0:
                internalScriptsCount = htmlhandler.countInternalScripts(bsObject, domain)
                if internalScriptsCount > 0:
                    analysisResults['status'] = 'malicious'
                    analysisResults['details'] = 'webpage contains escaped characters, xml processing instructions and additional internal scripts'
                else:
                    doScriptsInjectXML = htmlhandler.scriptsInjectXML(bsObject)
                    if doScriptsInjectXML:
                        analysisResults['status'] = 'malicious'
                        analysisResults['details'] = 'webpage contains escaped characters, xml processing instructions and its inline scripts inject XML'
                    else:
                        analysisResults['status'] = 'benign'
                        analysisResults['details'] = 'no malicious properties detected'
            else:
                analysisResults['status'] = 'benign'
                analysisResults['details'] = 'no malicious properties detected'    
    return analysisResults			

def checkByScoringMechanism(html, scoringParametersPath, domain = None):

    scoringchecker.setScoringParameters(scoringParametersPath)	
    analysisResults = {'status':'not classified', 'details':''}
    scores = scoringchecker.calculateScores(html, domain)
    explanations = scoringchecker.generateMaliciousExplanations(scores)
	
    if len(explanations) > 0:
        analysisResults['status'] = 'malicious'
        analysisResults['details'] = "; ".join(explanations)		
    else:	
        analysisResults['status'] = 'benign'
        analysisResults['details'] = 'no malicious properties detected'
    return analysisResults 

def checkByYaraRules(html, yaraRulesPath):
    analysisResults = {'status':'not classified', 'details':''}
    yarachecker.setYaraRulesObject(yaraRulesPath)
    matches = yarachecker.getYaraMatches(html)
    maliciousProperties = []
    for match in matches:
        matchedRule = match.rule
        maliciousProperty = rulesInterpretation[matchedRule]
        maliciousProperties.append(maliciousProperty)  
    if len(maliciousProperties) > 0:
        analysisResults['status'] = 'malicious'
        maliciousProperties = list(dict.fromkeys(maliciousProperties))
        analysisResults['details'] = "; ".join(maliciousProperties)           
    else:
        analysisResults['status'] = 'benign'
        analysisResults['details'] = 'no malicious properties detected'	
    return analysisResults
	
def checkWebpages(webpagesList, method, yaraRulesPath = None, scoringParametersPath = None):
    pageIndex = 1
    totalPages = len(webpagesList)
    results = []
    if method != 'random' and method != 'all' and method not in supportedAlgorithms:
        raise UnsupportedCheckingAlgorithmException("Supported checking algorithms:", supportedAlgorithms, 'random', 'all')
    for webpage in webpagesList:
        print(method, ':' , pageIndex , '/' , totalPages)
        if method == 'random':
            randomMethod = random.choice(supportedAlgorithms)
            analysisResult = analyzeWebpage(webpage, randomMethod, yaraRulesPath = yaraRulesPath, scoringParametersPath = scoringParametersPath)
            results.append(analysisResult)
        elif method == 'all':
            for algorithm in supportedAlgorithms:
                analysisResult = analyzeWebpage(webpage, algorithm, yaraRulesPath = yaraRulesPath, scoringParametersPath = scoringParametersPath)
                results.append(analysisResult)
        else:
            analysisResult = analyzeWebpage(webpage, method, yaraRulesPath = yaraRulesPath, scoringParametersPath = scoringParametersPath) 
            results.append(analysisResult)
        pageIndex += 1
    return results

def analyzeWebpage(webpage, algorithm, yaraRulesPath = None, scoringParametersPath = None):
    if algorithm not in supportedAlgorithms:
        raise UnsupportedCheckingAlgorithmException("Supported checking algorithms:", supportedAlgorithms)
    if algorithm == 'yara rules' and yaraRulesPath is None:
        raise YaraRulesPathNotSetException("Yara rules path is not set")
    if algorithm == 'static heuristics':
        checkupResult = checkByStaticHeuristics(webpage['html'])
        analysisResult = {key:webpage[key] for key in webpage if key!='html'}
        analysisResult['algorithm'] = 'static heuristics'
        analysisResult['status'] = checkupResult['status']
        analysisResult['details'] = checkupResult['details']	
    elif algorithm == 'scoring mechanism':
        checkupResult = checkByScoringMechanism(webpage['html'], scoringParametersPath)
        analysisResult = {key:webpage[key] for key in webpage if key!='html'}
        analysisResult['algorithm'] = 'scoring mechanism'
        analysisResult['status'] = checkupResult['status']
        analysisResult['details'] = checkupResult['details']
    elif algorithm == 'yara rules':
        checkupResult = checkByYaraRules(webpage['html'], yaraRulesPath)
        analysisResult = {key:webpage[key] for key in webpage if key!='html'}
        analysisResult['algorithm'] = 'yara rules'
        analysisResult['status'] = checkupResult['status']
        analysisResult['details'] = checkupResult['details']		
    return analysisResult