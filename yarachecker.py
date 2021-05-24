import yara

yaraRules = None

rulesInterpretation = {
'zerox88_js2': '0x88 Exploit Kit detected in JavaScript code',
'zerox88_js3': '0x88 Exploit Kit detected in JavaScript code',
'angler_ek_checkpoint': 'Angler Exploit Kit checkpoint detected',
'AnglerEKredirector': 'Angler Exploit Kit redirector detected',
'angler_html': 'Angler Exploit Kit detected in HTML code',
'angler_html2': 'Angler Exploit Kit detected in HTML code',
'angler_js': 'Angler Exploit Kit detected in JavaScript code',
'blackhole_basic': 'Blackhole Exploit kit usage detected',
'eleonore_js': 'Elenore Exploit Kit detected in JavaScript code',
'eleonore_js2': 'Elenore Exploit Kit detected in JavaScript code',
'eleonore_js3': 'Elenore Exploit Kit detected in JavaScript code',
'fragus_htm': 'Fragus Exploit Kit detected in HTML code',
'fragus_js': 'Fragus Exploit Kit detected in JavaScript code',
'fragus_js2': 'Fragus Exploit Kit detected in JavaScript code',
'fragus_js_flash': 'Fragus Exploit Kit with Flash object detected in Javascript code',
'fragus_js_vml': 'Fragus Exploit Kit with VML code detected in JavaScript code',
'generic_javascript_obfuscation': 'JavaScript obfuscation detected',
'possible_includes_base64_packed_functions ': 'Possible includes and packed functions detected',
'BeEF_browser_hooked': 'Possible browser hooking detection using Browser Exploatation Framework detected',
'src_ptheft_command': 'Possible confidential data theft using Browser Exploitation Framework detected',
'phoenix_html': 'Phoenix Exploit Kit detected in HTML code',
'phoenix_html10': 'Phoenix Exploit Kit detected in HTML code',
'phoenix_html11': 'Phoenix Exploit Kit detected in HTML code',
'phoenix_html2': 'Phoenix Exploit Kit detected in HTML code',
'phoenix_html3': 'Phoenix Exploit Kit detected in HTML code',
'phoenix_html4': 'Phoenix Exploit Kit detected in HTML code',
'phoenix_html5': 'Phoenix Exploit Kit detected in HTML code',
'phoenix_html6': 'Phoenix Exploit Kit detected in HTML code',
'phoenix_html7': 'Phoenix Exploit Kit detected in HTML code',
'phoenix_html8': 'Phoenix Exploit Kit detected in HTML code',
'phoenix_html9': 'Phoenix Exploit Kit detected in HTML code',
'redkit_bin_basic': 'Red Kit Exploit Kit usage detected',
'zeus_js': 'Zeus Exploit Kit detected in JavaScript code',
'zeroaccess_css': 'Zeroaccess Exploit Kit detected in CSS code',
'zeroaccess_css2': 'Zeroaccess Exploit Kit detected in CSS code',
'zeroaccess_htm': 'Zeroaccess Exploit Kit detected in HTML code',
'zeroaccess_js': 'Zeroaccess Exploit Kit detected in JavaScript code',
'zeroaccess_js2': 'Zeroaccess Exploit Kit detected in JavaScript code',
'zeroaccess_js3': 'Zeroaccess Exploit Kit detected in JavaScript code',
'zeroaccess_js4': 'Zeroaccess Exploit Kit detected in JavaScript code',
'blackhole2_css': 'Blackhole Exploit Kit detected in CSS code',
'blackhole2_htm': 'Blackhole Exploit Kit detected in HTML code',
'blackhole2_htm10': 'Blackhole Exploit Kit detected in HTML code',
'blackhole2_htm11': 'Blackhole Exploit Kit detected in HTML code',
'blackhole2_htm12': 'Blackhole Exploit Kit detected in HTML code',
'blackhole2_htm3': 'Blackhole Exploit Kit detected in HTML code',
'blackhole2_htm4': 'Blackhole Exploit Kit detected in HTML code',
'blackhole2_htm5': 'Blackhole Exploit Kit detected in HTML code',
'blackhole2_htm6': 'Blackhole Exploit Kit detected in HTML code',
'blackhole2_htm8': 'Blackhole Exploit Kit detected in HTML code',
} 

class YaraRulesNotSetException(Exception):
    pass

def setYaraRulesObject(path):
    global yaraRules
    yaraRulesFile = open(path, encoding='utf-8')
    yaraRulesString = yaraRulesFile.read()
    yaraRulesFile.close();
    yaraRules = yara.compile(source = yaraRulesString)
	
def getYaraMatches(html):
    if yaraRules is None:
        raise YaraRulesNotSetException("Yara rules object not set")
    matches = yaraRules.match(data=html)
    return matches