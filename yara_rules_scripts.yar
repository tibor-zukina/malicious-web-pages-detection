rule generic_javascript_obfuscation
{
meta:
	author = "Josh Berry"
	date = "2016-06-28"
	description = "JavaScript Obfuscation Detection"
	sample_filetype = "js-html"
strings:
	$string0 = /eval\(([\s]+)?(unescape|atob)\(/ nocase
	$string1 = /var([\s]+)?([a-zA-Z_$])+([a-zA-Z0-9_$]+)?([\s]+)?=([\s]+)?\[([\s]+)?\"\\x[0-9a-fA-F]+/ nocase
	$string2 = /var([\s]+)?([a-zA-Z_$])+([a-zA-Z0-9_$]+)?([\s]+)?=([\s]+)?eval;/
condition:
	any of them
}

rule possible_includes_base64_packed_functions  
{ 
	meta: 
		impact = 5 
		hide = true 
		desc = "Detects possible includes and packed functions" 
	strings: 
		$f = /(atob|btoa|;base64|base64,)/ nocase
		$fff = /([A-Za-z0-9]{4})*([A-Za-z0-9]{2}==|[A-Za-z0-9]{3}=|[A-Za-z0-9]{4})/ 
	condition: 
		$f and $fff
} 