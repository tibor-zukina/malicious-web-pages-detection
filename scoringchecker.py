import json
import lexicutils
import htmlhandler
from statistics import mean, stdev

class ScoringParametersNotSetException(Exception):
    pass

scoringParameters = None

def setScoringParameters(path):
    global scoringParameters
    scoringParametersFile = open(path, encoding='utf-8')
    scoringParametersString = scoringParametersFile.read()
    scoringParametersFile.close();
    scoringParameters = json.loads(scoringParametersString)

def calculateScores(html, domain = None):
    scores = {'foreign': {}, 'scripts': {}, 'exploit': {}}
    soup = htmlhandler.makeBeautifulSoup(html)
	
    scores['foreign']['redirectsCount'] = htmlhandler.countRedirects(soup)
    scores['foreign']['iframesCount'] = htmlhandler.countIFrameTags(soup)
    iframeLinksStatistics = htmlhandler.getIFrameLinksStatistics(soup)
    scores['foreign']['iframeLinksMedianLength'] = iframeLinksStatistics['medianLength']
    scores['foreign']['iframeLinksMinVowelRatio'] = iframeLinksStatistics['minVowelRatio']
    scores['foreign']['iframeLinksMinSpecialCharRatio'] = iframeLinksStatistics['minSpecialCharRatio']
    linksStatistics = htmlhandler.getLinksStatistics(soup, domain)
    scores['foreign']['minLinkLength'] = linksStatistics['minLength']
    scores['foreign']['externalLinks'] = linksStatistics['externalLinks']
    
    scores['scripts']['scriptsCount'] = htmlhandler.countScriptTags(soup)
    scriptStatistics = htmlhandler.getScriptStatistics(soup)
    scores['scripts']['linesNumber'] = scriptStatistics['linesNumber']
    scores['scripts']['wordsNumber'] = scriptStatistics['wordsNumber']
    scores['scripts']['specialCharRatio'] = scriptStatistics['specialCharRatio']
    scores['scripts']['minimumScriptLength'] = scriptStatistics['minimumScriptLength']
    scores['scripts']['minimumLineLength'] = scriptStatistics['minimumLineLength']
    scores['scripts']['maximumStringLength'] = scriptStatistics['maximumStringLength']
    scores['scripts']['minimumWordLength'] = scriptStatistics['minimumWordLength']
    scores['scripts']['minimumFunctionArgLength'] = scriptStatistics['minimumFunctionArgLength']
    
    scores['exploit']['objectsCount'] = htmlhandler.countObjectTags(soup)
    objectStatistics = htmlhandler.getObjectStatistics(soup)
    scores['exploit']['objectsMaxLinkLength'] = objectStatistics['maxLinkLength']
    scores['exploit']['objectLinksVowelRatio'] = objectStatistics['vowelRatio']
    scores['exploit']['objectLinksSpecialCharRatio'] = objectStatistics['specialCharRatio']
    scores['exploit']['objectsMedianAttributesNumber'] = objectStatistics['medianAttributesNumber']
    return scores
	
def prepareScoringParameters(webpagesList, path):
    scoringParameters = {"foreignThreshold": 10.2, "scriptsThreshold": 6.0, "exploitThreshold": 5.0, "foreign": {}, "scripts": {}, "exploit": {}}
    scoresList = {"foreign": {}, "scripts": {}, "exploit": {}}
    pageIndex = 1
    totalPages = len(webpagesList)
    for webpage in webpagesList:
        print("Analyzing page:", pageIndex, "/", totalPages)
        htmlScores = calculateScores(webpage['html'])
        foreignScores = htmlScores['foreign']
        scriptsScores = htmlScores['scripts']
        exploitScores = htmlScores['exploit']
        for foreignKey in list(foreignScores.keys()):
            if foreignKey not in scoresList['foreign']:
                scoresList['foreign'][foreignKey] = []
            scoresList['foreign'][foreignKey].append(foreignScores[foreignKey])
        for scriptsKey in list(scriptsScores.keys()):
            if scriptsKey not in scoresList['scripts']:
                scoresList['scripts'][scriptsKey] = []
            scoresList['scripts'][scriptsKey].append(scriptsScores[scriptsKey])
        for exploitKey in list(exploitScores.keys()):
            if exploitKey not in scoresList['exploit']:
                scoresList['exploit'][exploitKey] = []
            scoresList['exploit'][exploitKey].append(exploitScores[exploitKey])
        pageIndex += 1
    foreignScoresList = scoresList['foreign']
    scriptsScoresList = scoresList['scripts']
    exploitScoresList = scoresList['exploit']
    for foreignKey in list(foreignScoresList.keys()):
        scoringParameters['foreign'][foreignKey] = {}
        scoringParameters['foreign'][foreignKey]['average'] = mean(foreignScoresList[foreignKey])
        scoringParameters['foreign'][foreignKey]['deviation'] = stdev(foreignScoresList[foreignKey])
    for scriptsKey in list(scriptsScoresList.keys()):
        scoringParameters['scripts'][scriptsKey] = {}
        scoringParameters['scripts'][scriptsKey]['average'] = mean(scriptsScoresList[scriptsKey])
        scoringParameters['scripts'][scriptsKey]['deviation'] = stdev(scriptsScoresList[scriptsKey])
    for exploitKey in list(exploitScoresList.keys()):
        scoringParameters['exploit'][exploitKey] = {}
        scoringParameters['exploit'][exploitKey]['average'] = mean(exploitScoresList[exploitKey])
        scoringParameters['exploit'][exploitKey]['deviation'] = stdev(exploitScoresList[exploitKey])
    scoringParametersFile = open(path, "w", encoding='utf-8')
    scoringParametersFile.write(json.dumps(scoringParameters))
    scoringParametersFile.close()
	
def generateMaliciousExplanations(scores):
    if scoringParameters is None:
        raise ScoringParametersNotSetException("Scoring parameters not set")
    foreignResult = 0
    scriptsResult = 0
    exploitResult = 0    
    maliciousExplanations = []
	
    foreignScores = scores['foreign']
    foreignParameters = scoringParameters['foreign']
    scriptsScores = scores['scripts']
    scriptsParameters = scoringParameters['scripts']
    exploitScores = scores['exploit']
    exploitParameters = scoringParameters['exploit']
    foreignThreshold = scoringParameters['foreignThreshold']
    scriptsThreshold = scoringParameters['scriptsThreshold']
    exploitThreshold = scoringParameters['exploitThreshold']
    
    for foreignKey in list(foreignScores.keys()):
        foreignResult += abs(foreignScores[foreignKey]-foreignParameters[foreignKey]['average'])/foreignParameters[foreignKey]['deviation']
    for scriptsKey in list(scriptsScores.keys()):
        scriptsResult += abs(scriptsScores[scriptsKey]-scriptsParameters[scriptsKey]['average'])/scriptsParameters[scriptsKey]['deviation']
    for exploitKey in list(exploitScores.keys()):
        exploitResult += abs(exploitScores[exploitKey]-exploitParameters[exploitKey]['average'])/exploitParameters[exploitKey]['deviation']
    
    if foreignResult > foreignThreshold:
        maliciousExplanations.append('Foreign content score passed threshold of ' + str(foreignThreshold) + ' with result ' + str(foreignResult))
    if scriptsResult > scriptsThreshold:
        maliciousExplanations.append('Scripts content score passed threshold of ' + str(scriptsThreshold) + ' with result ' + str(scriptsResult))
    if exploitResult > exploitThreshold:
        maliciousExplanations.append('Exploit content score passed threshold of ' + str(exploitThreshold) + ' with result ' + str(exploitResult))
		
    return maliciousExplanations