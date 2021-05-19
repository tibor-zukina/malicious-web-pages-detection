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
	
def readHTMLFromFile(path):
    htmlFile = open(path)
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
	
def writeHTMLToFile(path, html):
    htmlFile = open(path, "w")
    htmlFile.write(html)
    htmlFile.close()