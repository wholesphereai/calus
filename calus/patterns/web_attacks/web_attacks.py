"""Category: web_attacks — XSS / CSRF / SSRF / SSTI / open-redirect payloads
that show up in agent-rendered content, tool outputs, or RAG documents."""
PATTERNS = [
 {'id':'WEB-XSS-001','severity':'high','category':'web_attacks','message':'Script-tag XSS payload','patterns':[r'(?i)<script\b[^>]*>[\s\S]*?</script>', r'(?i)<script\b[^>]*src\s*=']},
 {'id':'WEB-XSS-002','severity':'high','category':'web_attacks','message':'Event-handler XSS (onerror/onload/onclick)','patterns':[r'(?i)\bon(?:error|load|click|mouseover|focus)\s*=\s*["\']?[^"\'>]*(?:alert|eval|fetch|document\.)']},
 {'id':'WEB-XSS-003','severity':'high','category':'web_attacks','message':'javascript: URI scheme injection','patterns':[r'(?i)javascript:\s*(?:alert|eval|document|window|fetch)']},
 {'id':'WEB-XSS-004','severity':'high','category':'web_attacks','message':'Cookie/session theft via document.cookie','patterns':[r'(?i)document\.cookie', r'(?i)(?:fetch|XMLHttpRequest|navigator\.sendBeacon)\([^)]*document\.cookie']},
 {'id':'WEB-XSS-005','severity':'medium','category':'web_attacks','message':'Image/SVG onerror XSS vector','patterns':[r'(?i)<img\b[^>]*\bonerror\s*=', r'(?i)<svg\b[^>]*\bonload\s*=']},
 {'id':'WEB-XSS-006','severity':'medium','category':'web_attacks','message':'Iframe injection','patterns':[r'(?i)<iframe\b[^>]*src\s*=\s*["\']?\s*(?:javascript:|data:text/html)']},
 {'id':'WEB-CSRF-001','severity':'high','category':'web_attacks','message':'CSRF auto-submit form payload','patterns':[r'(?i)<form\b[^>]*action\s*=[^>]*>[\s\S]*?<input\b[^>]*type\s*=\s*["\']?hidden', r'(?i)\.submit\(\)\s*;?\s*</script>']},
 {'id':'WEB-SSRF-001','severity':'high','category':'web_attacks','message':'SSRF to cloud metadata endpoint','patterns':[r'(?i)(?:http://)?169\.254\.169\.254', r'(?i)metadata\.google\.internal', r'(?i)http://\[?fd00:ec2::254\]?']},
 {'id':'WEB-SSRF-002','severity':'medium','category':'web_attacks','message':'SSRF to internal/localhost from untrusted content','patterns':[r'(?i)(?:fetch|curl|wget|requests\.get)\([^)]*(?:127\.0\.0\.1|localhost|0\.0\.0\.0|::1)']},
 {'id':'WEB-SSTI-001','severity':'high','category':'web_attacks','message':'Server-side template injection (Jinja/Twig)','patterns':[r'\{\{\s*[\w.]*(?:config|self|request|__class__|__globals__|__mro__|cycler|joiner)\b', r'\{\%\s*(?:import|include|extends)\s']},
 {'id':'WEB-SSTI-002','severity':'high','category':'web_attacks','message':'Python object traversal RCE gadget','patterns':[r'(?i)__class__\s*\.\s*__(?:mro|bases|subclasses|globals)__', r'(?i)__import__\(\s*["\']os["\']']},
 {'id':'WEB-REDIR-001','severity':'medium','category':'web_attacks','message':'Open-redirect / URL-based phishing','patterns':[r'(?i)(?:redirect|return_?url|next|continue)=https?%3a%2f%2f', r'(?i)\b(?:url|redirect)=//[a-z0-9.-]+\.[a-z]{2,}']},
 {'id':'WEB-HDR-001','severity':'medium','category':'web_attacks','message':'HTTP header / CRLF injection','patterns':[r'(?:%0d%0a|\\r\\n)(?:Set-Cookie|Location|Content-Length)\s*:']},
]
