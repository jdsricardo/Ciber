import ssl,time
from http.client import HTTPConnection,HTTPSConnection
from urllib.parse import urlparse
from .models import HttpRequest,HttpResponse
from .safety import SafetyController

class HttpTransport:
    def __init__(self,safety:SafetyController):self.safety=safety
    def send(self,request:HttpRequest)->HttpResponse:
        self.safety.before_request(request);p=urlparse(request.url);path=p.path or "/"
        if p.query:path+="?"+p.query
        cls=HTTPSConnection if p.scheme=="https" else HTTPConnection;options={"timeout":self.safety.context.limits.request_timeout_seconds}
        if p.scheme=="https":options["context"]=ssl.create_default_context()
        conn=cls(p.hostname,p.port,**options);started=time.monotonic();headers={"User-Agent":"SentinelScope/2.0 authorized-security-scan","Accept":"text/html,application/json,*/*;q=0.5",**request.headers}
        conn.request(request.method,path,body=request.body or None,headers=headers);raw=conn.getresponse();tls=None;certificate={}
        if p.scheme=="https" and conn.sock:tls=conn.sock.version();certificate=conn.sock.getpeercert()
        body=raw.read(self.safety.context.limits.max_response_bytes);pairs=raw.getheaders();response_headers={k.lower():v for k,v in pairs};elapsed=round((time.monotonic()-started)*1000)
        response=HttpResponse(raw.status,request.url,response_headers,pairs,body,elapsed,response_headers.get("location"),tls,certificate);conn.close()
        self.safety.log({"event":"response","number":self.safety.total,"status":response.status,"bytes":len(body),"elapsed_ms":elapsed})
        return response
