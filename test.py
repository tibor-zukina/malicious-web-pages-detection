import pagefetch
import pagechecker
from pprint import pprint
from testutils import filterBenign, filterMalicious, loadExpectedResults, generateCsvReport, writeResultToFile
	
def staticHeuristicsDatabaseTest(connectionString, databaseName, collectionName, numberOfPages, offset = 0, expectedResultsPath = None):
    pagefetch.setMongoConnection(connectionString, databaseName, collectionName)
    htmlList = pagefetch.fetchMongoHTMLSet(numberOfPages, offset)
    checkResult = pagechecker.checkWebpages(htmlList,'static heuristics')
    displayResults(checkResult, 'static heuristics', expectedResultsPath)

def scoringMechanismDatabaseTest(connectionString, databaseName, collectionName, numberOfPages, offset = 0, expectedResultsPath = None):
    pagefetch.setMongoConnection(connectionString, databaseName, collectionName)
    htmlList = pagefetch.fetchMongoHTMLSet(numberOfPages, offset)
    checkResult = pagechecker.checkWebpages(htmlList,'scoring mechanism')
    displayResults(checkResult, 'scoring mechanism', expectedResultsPath)
	
def yaraRulesDatabaseTest(connectionString, databaseName, collectionName, numberOfPages, offset = 0, expectedResultsPath = None):
    pagefetch.setMongoConnection(connectionString, databaseName, collectionName)
    htmlList = pagefetch.fetchMongoHTMLSet(numberOfPages, offset)
    checkResult = pagechecker.checkWebpages(htmlList,'yara rules')
    displayResults(checkResult, 'yara rules', expectedResultsPath)
	
def staticHeuristicsDirectoryTest(directoryPath):
    htmlList = pagefetch.readHTMLListFromDir(directoryPath)
    checkResult = pagechecker.checkWebpages(htmlList,'static heuristics')
    displayResults(checkResult, 'static heuristics')
	
def scoringMechanismDirectoryTest(directoryPath):
    htmlList = pagefetch.readHTMLListFromDir(directoryPath)
    checkResult = pagechecker.checkWebpages(htmlList,'scoring mechanism')
    displayResults(checkResult, 'scoring mechanism')

def yaraRulesDirectoryTest(directoryPath):
    htmlList = pagefetch.readHTMLListFromDir(directoryPath)
    checkResult = pagechecker.checkWebpages(htmlList,'yara rules')
    displayResults(checkResult, 'yara rules')
	
def staticHeuristicsURLListTest(urlList):
    htmlList = pagefetch.fetchRawHTMLList(urlList)
    checkResult = pagechecker.checkWebpages(htmlList,'static heuristics')
    displayResults(checkResult, 'static heuristics')
	
def scoringMechanismURLListTest(urlList):
    htmlList = pagefetch.fetchRawHTMLList(urlList)
    checkResult = pagechecker.checkWebpages(htmlList,'scoring mechanism')
    displayResults(checkResult, 'scoring mechanism')

def yaraRulesURLListTest(urlList):
    htmlList = pagefetch.fetchRawHTMLList(urlList)
    checkResult = pagechecker.checkWebpages(htmlList,'yara rules')
    displayResults(checkResult, 'yara rules')
		
def displayResults(results, algorithm, expectedResultsPath = None):
    print("Displaying results with {0} algorithm analysis".format(algorithm))
    print("All pages:")
    pprint(results)
    if expectedResultsPath is not None:
        expectedResults = loadExpectedResults(expectedResultsPath) 
    else:
        expectedResults = None
    statistics = resultsStatistics(results, expectedResults) 
    print("Benign pages:")
    pprint(statistics['benignResults'])
    print("Malicious pages:")
    pprint(statistics['maliciousResults'])
    print("Total number of analyzed pages: {0}".format(statistics['totalNumber']))
    print("Number of benign pages: {0}".format(statistics['benignNumber']))
    print("Number of malicious pages: {0}".format(statistics['maliciousNumber']))
    print("Percentage of benign pages: {0}%".format(statistics['benignPercentage']))
    print("Percentage of malicious pages: {0}%".format(statistics['maliciousPercentage']))
    if expectedResultsPath is not None:
        print("Number of false positives: {0}".format(statistics['falsePositives']))
        print("Number of true negatives: {0}".format(statistics['trueNegatives']))
        print("Number of false negatives: {0}".format(statistics['falseNegatives']))
        print("Number of true positives: {0}".format(statistics['truePositives']))
        print("False positive rate: {0} %".format(statistics['falsePositiveRate']))
        print("False negative rate: {0} %".format(statistics['falseNegativeRate']))
		
def compareAlgorithms(connectionString, databaseName, collectionName, algorithm1, algorithm2, numberOfPages, offset = 0):
    pagefetch.setMongoConnection(connectionString, databaseName, collectionName)
    htmlList = pagefetch.fetchMongoHTMLSet(numberOfPages, offset)
    firstResults = pagechecker.checkWebpages(htmlList, algorithm1)
    secondResults = pagechecker.checkWebpages(htmlList, algorithm2)
    displayResults(firstResults, algorithm1)
    displayResults(secondResults, algorithm2)
    compareResults(firstResults, secondResults, algorithm1, algorithm2)
   
def compareResults(firstResults, secondResults, algorithm1, algorithm2):
    matchingResults = 0
    print("Results comparison for {0} algorithm and {1} algorithm:".format(algorithm1, algorithm2))
    for result1, result2 in list(zip(firstResults, secondResults)):
        if(result1['status'] == result2['status']):
            matchingResults += 1
            print("Results for id {0} match".format(result1['id']))
        else:
            print("Results for id {0} do not match".format(result1['id']))
            printResult1 = {key:result1[key] for key in result1 if key!='id' and key!='algorithm'}
            printResult2 = {key:result2[key] for key in result2 if key!='id' and key!='algorithm'}
            print("{0} result:".format(algorithm1))
            pprint(printResult1)
            print("{0} result:".format(algorithm2))
            pprint(printResult2)
    totalResults = len(firstResults)
    matchRate = round(matchingResults/totalResults*100,2);
    print("Match rate between {0} algorithm and {1} algorithm is {2}%".format(algorithm1, algorithm2, matchRate))

def analyzeAllAlgorithms(connectionString, databaseName, collectionName, numberOfPages, expectedResultsPath, analysisResultsPath, offset = 0):
    pagefetch.setMongoConnection(connectionString, databaseName, collectionName)
    htmlList = pagefetch.fetchMongoHTMLSet(numberOfPages, offset)
    
    staticHeuristicsResults = pagechecker.checkWebpages(htmlList,'static heuristics')
    scoringMechanismResults = pagechecker.checkWebpages(htmlList,'scoring mechanism')
    yaraRulesResults = pagechecker.checkWebpages(htmlList,'yara rules')
    expectedResults = loadExpectedResults(expectedResultsPath)
	
    staticStatistics = resultsStatistics(staticHeuristicsResults, expectedResults)
    scoringStatistics = resultsStatistics(scoringMechanismResults, expectedResults)
    yaraStatistics = resultsStatistics(yaraRulesResults, expectedResults)
    expectedStatistics = expectedResultsStatistics(expectedResults)
	
    allResults = generateCsvReport(staticHeuristicsResults, scoringMechanismResults, yaraRulesResults, expectedResults, staticStatistics, scoringStatistics, yaraStatistics, expectedStatistics)
    writeResultToFile(analysisResultsPath, allResults)  	
    
def resultsStatistics(results, expectedResults = None):
    analysisResult = {}
    analysisResult['benignResults'] = [result for result in results if result['status'] == 'benign']
    analysisResult['maliciousResults'] = [result for result in results if result['status'] == 'malicious']
    analysisResult['totalNumber'] = len(results)
    analysisResult['benignNumber'] = len(analysisResult['benignResults'])
    analysisResult['maliciousNumber'] = len(analysisResult['maliciousResults'])
    analysisResult['benignPercentage'] = round(analysisResult['benignNumber']/analysisResult['totalNumber']*100, 2)
    analysisResult['maliciousPercentage'] = round(analysisResult['maliciousNumber']/analysisResult['totalNumber']*100, 2)
    
    if expectedResults is not None:
        falsePositives = 0
        trueNegatives = 0
        falseNegatives = 0
        truePositives = 0
        for result in results:
            if result['status'] == 'benign':
                if expectedResults[result['id']] == 'benign':
                    trueNegatives += 1
                else:
                    falseNegatives += 1
            else:
                if expectedResult[result['id']] == 'malicious':
                    truePositives += 1
                else:
                    falsePositives += 1
        analysisResult['falsePositives'] = falsePositives
        analysisResult['trueNegatives'] = trueNegatives
        analysisResult['falseNegatives'] = falseNegatives
        analysisResult['truePositives'] = truePositives
        analysisResult['falsePositiveRate'] = round(falsePositives/(falsePositives+trueNegatives)*100,2)
        analysisResult['falseNegativeRate'] = round(falseNegatives/(falseNegatives+truePositives)*100,2)
    return analysisResult

def expectedResultsStatistics(expectedResults):
    analysisResult = {}
    analysisResult['benignResults'] = { key:value for (key,value) in expectedResults.items() if value == 'benign'}
    analysisResult['maliciousResults'] = { key:value for (key,value) in expectedResults.items() if value == 'malicious'}
    analysisResult['totalNumber'] = len(expectedResults.keys())
    analysisResult['benignNumber'] = len(analysisResult['benignResults'].keys())
    analysisResult['maliciousNumber'] = len(analysisResult['maliciousResults'].keys())
    analysisResult['benignPercentage'] = round(analysisResult['benignNumber']/analysisResult['totalNumber']*100, 2)
    analysisResult['maliciousPercentage'] = round(analysisResult['maliciousNumber']/analysisResult['totalNumber']*100, 2)
    return analysisResult
	
connectionString = open('connection_string', 'r').readline()
databaseName = 'websecradar'
collectionName = 'crawled_data_pages_v0'

#staticHeuristicsDatabaseTest(connectionString, databaseName, collectionName, 10)   
#scoringMechanismDatabaseTest(connectionString, databaseName, collectionName, 10)
#yaraRulesDatabaseTest(connectionString, databaseName, collectionName, 10)

directoryPath = 'list_test'

#staticHeuristicsDirectoryTest(directoryPath)
#scoringMechanismDirectoryTest(directoryPath)
#yaraRulesDirectoryTest(directoryPath)

urlList = ['https://www.fer.unizg.hr/','https://www.carnet.hr/']

#staticHeuristicsURLListTest(urlList)
#scoringMechanismURLListTest(urlList)
#yaraRulesURLListTest(urlList)

compareAlgorithms(connectionString, databaseName, collectionName, 'static heuristics', 'scoring mechanism', 10, offset = 0)
#compareAlgorithms(connectionString, databaseName, collectionName, 'static heuristics', 'yara rules', 10, offset = 0)
#compareAlgorithms(connectionString, databaseName, collectionName, 'scoring mechanism', 'yara rules', 10, offset = 0)

#staticHeuristicsDatabaseTest(connectionString, databaseName, collectionName, 10, expectedResultsPath = 'test/expected_results.csv')
analyzeAllAlgorithms(connectionString, databaseName, collectionName, 10, 'test/expected_results.csv', 'test/analysis_results.csv')