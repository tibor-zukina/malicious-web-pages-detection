import re

def vowelRatio(str):
    vowel = ['a', 'e', 'i', 'o', 'u', 'A', 'E', 'I', 'O', 'U']
    vowelCount = 0
    for letter in str:
        if letter in vowel:
            vowelCount += 1
    letterCount = len(str)
    if(letterCount > 0):
        ratio = vowelCount/letterCount
    else:
        ratio = 0.00
    return ratio

def specialCharRatio(str):
    specialChar = [';', '+=', '_', '?', '=', '&', '[', ']', '#', '~', '%', '@', '$', '*', '+', '!', '|']
    specialCharCount = 0
    for letter in str:
        if letter in specialChar:
            specialCharCount += 1
    letterCount = len(str)
    if(letterCount > 0):
        ratio = specialCharCount/letterCount
    else:
        ratio = 0.00
    return ratio

def linesNumber(str):
    return len(str.splitlines())
	
def wordsNumber(str):
    return len(str.split())
	
def minimumLineLength(str):
    lines = str.splitlines()
    if (len(lines) > 0):
        return len(min(lines, key=len))
    else:
        return 0	
	
def maximumStringLength(str):
    stringsList = re.findall("['\"]([0-9a-zA-Z\.\?\+\*\^\$\\\(\)\[\]\{\}\|]*)['\"]",str)
    if (len(stringsList) > 0):
        return len(max(stringsList, key = len))
    else:
        return 0

def minimumWordLength(str):
    words = str.split()
    if (len(words) > 0):
        return len(min(words, key=len))
    else:
        return 0
		
def minimumFunctionArgLength(str):
    argumentsList = []
    functionOccurances = re.findall('function[ \t]+[A-Za-z_][0-9A-Za-z_]+[ \t]*\([a-zA-Z0-9 _,]+\)', str)
    for functionOccurance in functionOccurances:
        argumentsString = functionOccurance.split('(')[1].replace(')','').replace(' ','')
        argumentsList = argumentsList + argumentsString.split(',')
    if (len(argumentsList) > 0):
        return len(min(argumentsList, key = len))
    else:
        return 0

	
	