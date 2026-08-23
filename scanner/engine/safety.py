from __future__ import annotations
import json, os, socket, time
from collections import Counter
from ipaddress import ip_address
from threading import Lock
from urllib.parse import urljoin, urlparse
from .models import HttpRequest, HttpResponse, ScanContext

SENSITIVE_HEADERS={"authorization","cookie","proxy-authorization","x-api-key"}
class Cancelled(RuntimeError): pass
class BudgetExceeded(RuntimeError): pass
class ScopeViolation(ValueError): pass

def mask(value:str)->str:
    if len(value)<8:return "***"
    return value[:3]+"***"+value[-2:]
def redact_headers(headers):return {k:(mask(v) if k.lower() in SENSITIVE_HEADERS else v) for k,v in headers.items()}

class SafetyController:
    def __init__(self,context:ScanContext):
        self.context=context;self.started=time.monotonic();self.total=0;self.per_endpoint=Counter();self.last_request=0.0;self.lock=Lock()
        parsed=urlparse(context.target_url);self.scheme=parsed.scheme;self.host=parsed.hostname;self.port=parsed.port or (443 if parsed.scheme=="https" else 80)
        if self.scheme not in ("http","https") or not self.host:raise ScopeViolation("Only absolute HTTP(S) targets are supported")
        self.pinned_addresses=self._resolve(self.host)
    def _resolve(self,host):
        addresses={item[4][0].split('%')[0] for item in socket.getaddrinfo(host,None)}
        if not addresses:raise ScopeViolation("Target did not resolve")
        if not self.context.allow_private and any(not ip_address(x).is_global for x in addresses):raise ScopeViolation("Private, loopback, link-local, and reserved targets are blocked")
        return addresses
    def validate_url(self,url):
        p=urlparse(url);port=p.port or (443 if p.scheme=="https" else 80)
        if p.scheme not in ("http","https") or p.username or p.password:raise ScopeViolation("Unsafe URL scheme or embedded credentials")
        if p.hostname!=self.host or port!=self.port:raise ScopeViolation("Request attempted to leave the authorized host and port")
        current=self._resolve(p.hostname)
        if current!=self.pinned_addresses:raise ScopeViolation("DNS resolution changed during the scan")
    def before_request(self,request:HttpRequest):
        with self.lock:
            self.validate_url(request.url)
            if self.context.cancel_file and os.path.exists(self.context.cancel_file):raise Cancelled("Scan cancelled")
            if time.monotonic()-self.started>self.context.limits.global_timeout_seconds:raise BudgetExceeded("Global scan timeout reached")
            endpoint=f"{request.method}:{urlparse(request.url).path}"
            if self.total>=self.context.limits.max_requests:raise BudgetExceeded("Global request budget reached")
            if self.per_endpoint[endpoint]>=self.context.limits.max_requests_per_endpoint:raise BudgetExceeded("Endpoint request budget reached")
            wait=self.context.limits.min_request_interval_seconds-(time.monotonic()-self.last_request)
            if wait>0:time.sleep(wait)
            self.total+=1;self.per_endpoint[endpoint]+=1;self.last_request=time.monotonic()
            self.log({"event":"request","number":self.total,"method":request.method,"url":request.url,"headers":redact_headers(request.headers),"body_bytes":len(request.body)})
    def log(self,event):
        if not self.context.log_file:return
        event["timestamp"]=time.time()
        with open(self.context.log_file,"a",encoding="utf-8") as stream:stream.write(json.dumps(event,ensure_ascii=False)+"\n")

def safe_redirect(base,location,controller):
    target=urljoin(base,location);controller.validate_url(target);return target
