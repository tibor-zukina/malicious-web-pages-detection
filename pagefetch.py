import urllib.request

def fetchRawHTML(url):
    webURL = urllib.request.urlopen(url)
    html = webURL.read()
    return html
