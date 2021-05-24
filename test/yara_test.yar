rule rule1: TEST1
{
strings:
	$string1 = "abc"
	$string2 = "rtl"
condition:
	all of them
}

rule rule2: TEST2
{
strings:
	$string1 = "678"
	$string2 = "67eu"
condition:
	all of them
}

rule rule3: TEST3
{
strings:
	$string1 = "345"
	$string2 = "a67"
condition:
	all of them
}