import urllib.request
import json
from pymongo import MongoClient
from bson.objectid import ObjectId
from os import listdir
from os.path import isfile, join

mongoConnection = None
webpagesDatabaseName = None
webpagesCollectionName = None

class ConnectionNotSetException(Exception):
    pass

def fetchRawHTML(url):
    webURL = urllib.request.urlopen(url)
    html = webURL.read()
    return html

def fetchRawHTMLList(urlList):
    htmlList = []
    for url in urlList:
        html = fetchRawHTML(url)
        htmlList.append({'url': url, 'html' : html})
    return htmlList
        
def fetchHTTPResponse(url):
    webURL = urllib.request.urlopen(url)
    html = webURL.read()
    responseCode = webURL.getcode()
    webpage = {'html': html, 'responseCode': responseCode}	
    return webpage

def fetchHTTPResponseList(urls):
    htmlList = []
    for url in urlList:
        response = fetchHTTPResponse(url)
        htmlList.append({'url': url, 'html': response['html'], 'responseCode': response['responseCode'] })
    return htmlList
	
def setMongoConnection(connectionString, databaseName, collectionName):
    global mongoConnection, webpagesDatabaseName, webpagesCollectionName
    mongoConnection = MongoClient(connectionString)
    webpagesDatabaseName = databaseName
    webpagesCollectionName = collectionName
	
def fetchMongoHTML(pageId):
    if mongoConnection is None:
        raise ConnectionNotSetException("MongoDB connection not set")
    webpagesDatabase = mongoConnection[webpagesDatabaseName]
    webpagesCollection = webpagesDatabase[webpagesCollectionName]
    html = webpagesCollection.find_one({"_id": ObjectId(pageId)})['page'];
    return html
	
def fetchMongoHTMLList(pageIdList):
    htmlList = []
    for pageId in pageIdList:
        html = fetchMongoHTML(pageId)
        htmlList.append({'id': id, 'html': html})
    return htmlList
	
def fetchMongoHTMLSet(numberOfPages, offset = 0):
    if mongoConnection is None:
        raise ConnectionNotSetException("MongoDB connection not set")
    webpagesDatabase = mongoConnection[webpagesDatabaseName]
    webpagesCollection = webpagesDatabase[webpagesCollectionName]
    htmlSet = []
    htmlSetCursor = webpagesCollection.find({"page" : {'$regex' : '(^\<html\>)|(^\<!DOCTYPE HTML)', '$options': 'i'}},{ "_id": 1, "page": 1}).skip(offset).limit(numberOfPages)
    for html in htmlSetCursor:
        htmlSet.append({"id": str(html['_id']) , 'html': html['page']})
    return htmlSet
	
def fetchMongoHTMLDatabase(numberOfPages = 268000, offset = 0):
    if mongoConnection is None:
        raise ConnectionNotSetException("MongoDB connection not set")
    webpagesDatabase = mongoConnection[webpagesDatabaseName]
    urlsList = []
    hashList = []
    urlsCollection = webpagesDatabase['urls']
    urlCrawlsCollection = webpagesDatabase['crawled_data_urls_v0']
    webpagesCollection = webpagesDatabase['crawled_data_pages_v0']
    urlsSetCursor = urlsCollection.find({'redirects_to' : { '$exists' : False }, 'disabled' : { '$exists' : False }},{'_id': 0, 'url' : 1}).sort('_id').skip(offset).limit(numberOfPages)
    a = offset
    for url in urlsSetCursor:
        a += 1
        print(a)
        urlsList.append(url['url'])
        webpageUrl = url['url']
        urlCrawlsCursor = urlCrawlsCollection.find({'url' : { '$eq' : webpageUrl}},{'_id': 0, 'checks' : 1})
        for urlCrawl in urlCrawlsCursor:
            checks = urlCrawl['checks']
            hash = checks[-1]['hash']
            if hash is not None:
                webpagesCursor = webpagesCollection.find({'hash' : { '$eq' : hash }},{'page' : 1})
                for webpage in webpagesCursor:
                    htmlPath = 'database_webpages/' + str(webpage['_id'])
                    urlPath = 'database_webpage_urls/' + str(webpage['_id'])
                    writeHTMLToFile(htmlPath, webpage['page'])
                    writeHTMLToFile(urlPath, webpageUrl)                 
		
def readHTMLFromFile(path):
    htmlFile = open(path, encoding='utf-8')
    html = htmlFile.read()
    htmlFile.close();
    return html;

def readHTMLListFromDir(directory):
    htmlList = []
    pathList = []
    childList = listdir(directory)
    for child in childList:
        fullPath = join(directory, child)
        if isfile(fullPath):
            pathList.append(fullPath)		
    for path in pathList:
        html = readHTMLFromFile(path)
        htmlList.append({'path': path, 'html': html})
    return htmlList

def readHTMLListFromDatabaseDir(directory):
    htmlList = []
    pathList = []
    childList = listdir(directory)
    pageIndex = 1
    totalWebpages = len(childList)
    for child in childList:
        fullPath = join(directory, child)
        if isfile(fullPath):
            html = 	readHTMLFromFile(fullPath)	
            htmlList.append({'id': child, 'html': html})
            pageIndex += 1
            print('Loading page: ', pageIndex, '/', totalWebpages)
    return htmlList
	
def writeHTMLToFile(path, html):
    htmlFile = open(path, "w", encoding='utf-8')
    htmlFile.write(html)
    htmlFile.close()