# Malicious web pages detection

This repository contains the code for detecting injected malicous HTML and JavaScript fragments in Web pages.

HTML fetch functions usage:

# Raw HTML fetch from URL

websiteURL = 'https://example.com'

rawHTML = pagefetch.fetchRawHTML(websiteURL)

# Fetching HTML from MongoDB database

connectionString = 'mongodb://user:password@host:port'

databaseName = 'webpage_database'

collectionName = 'webpage_collection'


pagefetch.setMongoConnection(connectionString, databaseName, collectionName)

webpageId = 'unique_website_id'

mongoHTML = pagefetch.fetchMongoHTML(webpageId)

