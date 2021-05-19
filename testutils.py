def filterBenign(result):
    if result['status'] == 'benign':
        return True
    else:
        return False

def filterMalicious(result):
    if result['status'] == 'malicious':
        return True
    else:
        return False
		
def loadExpectedResults(path):
    expectedResults = {}
    csvFile = open(path)
    csvContent = csvFile.read()
    csvFile.close()
    for line in csvContent.splitlines():
        parts = line.split(',')
        id = parts[0]
        status = parts[1]
        expectedResults[id] = status
    return expectedResults

def generateCsvReport(staticHeuristicsResults, scoringMechanismResults, yaraRulesResults, expectedResults, staticStatistics, scoringStatistics, yaraStatistics, expectedStatistics):
    allResults = 'Page ID, Static heuristics status, Scoring mechanism status, Yara rules status, Expected status, Static heuristics details, Scoring mechanism details, Yara rules details'
    
    for result1, result2, result3 in list(zip(staticHeuristicsResults, scoringMechanismResults, yaraRulesResults)):
        pageId = result1['id']
        expectedStatus = expectedResults[pageId]
        csvEntry = pageId + ',' + result1['status'] + ',' + result2['status'] + ',' + result3['status'] + ',' + expectedStatus + ',' + result1['details'] + ',' + result2['details'] + ',' + result3['details']
        allResults = allResults + '\n' + csvEntry  
   
    totalNumberEntry = ',Total: ' + str(staticStatistics['totalNumber']) + ',Total: ' + str(scoringStatistics['totalNumber']) + ',Total: ' + str(yaraStatistics['totalNumber']) + ',Total: ' + str(expectedStatistics['totalNumber']) 
    benignNumberEntry = ',Benign: ' + str(staticStatistics['benignNumber']) + ',Benign: ' + str(scoringStatistics['benignNumber']) + ',Benign: ' + str(yaraStatistics['benignNumber']) + ',Benign: ' + str(expectedStatistics['benignNumber'])
    maliciousNumberEntry = ',Malicious: ' + str(staticStatistics['maliciousNumber']) + ',Malicious: ' + str(scoringStatistics['maliciousNumber']) + ',Malicious: ' + str(yaraStatistics['maliciousNumber']) + ',Malicious: ' + str(expectedStatistics['maliciousNumber'])
    benignPercentageEntry = ',Benign percentage: ' + str(staticStatistics['benignPercentage']) + '%,Benign percentage: ' + str(scoringStatistics['benignPercentage']) + '%,Benign percentage: ' + str(yaraStatistics['benignPercentage']) + '%,Benign percentage: ' + str(expectedStatistics['benignPercentage']) + '%'
    maliciousPercentageEntry = ',Malicious percentage: ' + str(staticStatistics['maliciousPercentage']) + '%,Malicious percentage: ' + str(scoringStatistics['maliciousPercentage']) + '%,Malicious percentage: ' + str(yaraStatistics['maliciousPercentage']) + '%,Malicious percentage: ' + str(expectedStatistics['maliciousPercentage']) + '%'
    falsePositivesEntry = ',False positives: ' + str(staticStatistics['falsePositives']) + ',False positives: ' + str(scoringStatistics['falsePositives']) + ',False positives: ' + str(yaraStatistics['falsePositives'])
    trueNegativesEntry = ',True negatives: ' + str(staticStatistics['trueNegatives']) + ',True negatives: ' + str(scoringStatistics['trueNegatives']) + ',True negatives: ' + str(yaraStatistics['trueNegatives'])
    falseNegativesEntry = ',False negatives: ' + str(staticStatistics['falseNegatives']) + ',False negatives: ' + str(scoringStatistics['falseNegatives']) + ',False negatives: ' + str(yaraStatistics['falseNegatives'])
    truePositivesEntry = ',True positives: ' + str(staticStatistics['truePositives']) + ',True positives: ' + str(scoringStatistics['truePositives']) + ',True positives: ' + str(yaraStatistics['truePositives'])
    falsePositiveRateEntry = ',False positive rate: ' + str(staticStatistics['falsePositiveRate']) + ',False positive rate: ' + str(scoringStatistics['falsePositiveRate']) + ',False positive rate: ' + str(yaraStatistics['falsePositiveRate']) + '%'
    falseNegativeRateEntry = ',False negative rate: ' + str(staticStatistics['falseNegativeRate']) + ',False negative rate: ' + str(scoringStatistics['falseNegativeRate']) + ',False negative rate: ' + str(yaraStatistics['falseNegativeRate']) + '%'
    allResults += '\n'
    allResults += '\n' + totalNumberEntry
    allResults += '\n' + benignNumberEntry
    allResults += '\n' + benignPercentageEntry
    allResults += '\n' + maliciousNumberEntry
    allResults += '\n' + maliciousPercentageEntry
    allResults += '\n' + falsePositivesEntry
    allResults += '\n' + trueNegativesEntry
    allResults += '\n' + falseNegativesEntry
    allResults += '\n' + truePositivesEntry
    allResults += '\n' + falsePositiveRateEntry
    allResults += '\n' + falseNegativeRateEntry
    return allResults

def writeResultToFile(path, result):
    csvFile = open(path, "w")
    csvFile.write(result)
    csvFile.close()	