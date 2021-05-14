import pagefetch
import pagechecker
from pprint import pprint

directoryPath = 'list_test'
htmlList = pagefetch.readHTMLListFromDir(directoryPath)
checkResult = pagechecker.checkWebpages(htmlList,'static heuristics')
pprint(checkResult)
