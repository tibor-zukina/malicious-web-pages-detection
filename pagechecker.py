import pageattributes
import htmlhandler
import random

supportedAlgorithms = ('static heuristics', 'scoring mechanism', 'yara rules')

class UnsupportedCheckingAlgorithmException(Exception):
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
            return analysisResults
        else:
            objectsNumber = htmlhandler.countObjectTags(bsObject)
            if objectsNumber > 0:
                analysisResults['status'] = 'malicious'
                analysisResults['details'] = 'webpage contains iframe elements and object elements'
                return analysisResults
            else:
                scriptsNumber = htmlhandler.countScriptTags(bsObject)
                if scriptsNumber > 4:
                    analysisResults['status'] = 'benign'
                    analysisResults['details'] = 'no malicious properties detected'
                    return analysisResults
                else:
                    analysisResults['status'] = 'benign'
                    analysisResults['details'] = 'no malicious properties detected'
                    return analysisResults
    else:
        obfuscationData = htmlhandler.detectObfuscation(bsObject)
        scriptsWithEscapedCharacters = obfuscationData['escaped_characters']
        if scriptsWithEscapedCharacters > 0:
            obfuscatedScripts = obfuscationData['obfuscated']
            if obfuscatedScripts > 0:
                analysisResults['status'] = 'malicious'
                analysisResults['details'] = 'obfuscated javascript code has been detected'
                return analysisResults
            else:
                analysisResults['status'] = 'benign'
                analysisResults['details'] = 'no malicious properties detected'
                return analysisResults	
        else:
            analysisResults['status'] = 'benign'
            analysisResults['details'] = 'no malicious properties detected'
            return analysisResults	

def checkByScoringMechanism(html, scoringParameters = None):
    analysisResults = {'status':'not classified', 'details':''}
    analysisResults['status'] = 'benign'
    analysisResults['details'] = 'scoring algorithm has not yet been implemented'
    return analysisResults 

def checkByYaraRules(html):
    analysisResults = {'status':'not classified', 'details':''}
    analysisResults['status'] = 'benign'
    analysisResults['details'] = 'yara algorithm has not yet been implemented'
    return analysisResults
	
def checkWebpages(webpagesList, method):
    results = []
    if method != 'random' and method != 'all' and method not in supportedAlgorithms:
        raise UnsupportedCheckingAlgorithmException("Supported checking algorithms:", supportedAlgorithms, 'random', 'all')
    for webpage in webpagesList:
        if method == 'random':
            randomMethod = random.choice(supportedAlgorithms)
            analysisResult = analyzeWebpage(webpage, randomMethod)
            results.append(analysisResult)
        elif method == 'all':
            for algorithm in supportedAlgorithms:
                analysisResult = analyzeWebpage(webpage, algorithm)
                results.append(analysisResult)
        else:
            analysisResult = analyzeWebpage(webpage, method) 
            results.append(analysisResult)
    return results

def analyzeWebpage(webpage, algorithm):
    if algorithm not in supportedAlgorithms:
        raise UnsupportedCheckingAlgorithmException("Supported checking algorithms:", supportedAlgorithms)
    if algorithm == 'static heuristics':
        checkupResult = checkByStaticHeuristics(webpage['html'])
        analysisResult = {key:webpage[key] for key in webpage if key!='html'}
        analysisResult['algorithm'] = 'static heuristics'
        analysisResult['status'] = checkupResult['status']
        analysisResult['details'] = checkupResult['details']	
    elif algorithm == 'scoring mechanism':
        checkupResult = checkByScoringMechanism(webpage['html'])
        analysisResult = {key:webpage[key] for key in webpage if key!='html'}
        analysisResult['algorithm'] = 'scoring mechanism'
        analysisResult['status'] = checkupResult['status']
        analysisResult['details'] = checkupResult['details']
    elif algorithm == 'yara rules':
        checkupResult = checkByYaraRules(webpage['html'])
        analysisResult = {key:webpage[key] for key in webpage if key!='html'}
        analysisResult['algorithm'] = 'yara rules'
        analysisResult['status'] = checkupResult['status']
        analysisResult['details'] = checkupResult['details']		
    return analysisResult