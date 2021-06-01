import pagefetch

connectionString = open('connection_string', 'r').readline()
databaseName = 'websecradar'
collectionName = 'crawled_data_pages_v0'

pagefetch.setMongoConnection(connectionString, databaseName, collectionName)
pagefetch.fetchMongoHTMLDatabase(offset = 101379)