import urllib.request
import json
from pymongo import MongoClient
from bson.objectid import ObjectId

mongoConnection = None
webpagesDatabaseName = None
webpagesCollectionName = None

class ConnectionNotSetException(Exception):
    pass

def fetchRawHTML(url):
    webURL = urllib.request.urlopen(url)
    html = webURL.read()
    return html

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