import json
import re
from dataclasses import dataclass
from typing import Any, Callable
from .models import HttpResponse, ResponseDiff

@dataclass
class MatchResult:
    matched: bool
    detail: str

class Matcher:
    def __init__(self,fn:Callable[[HttpResponse,ResponseDiff|None],MatchResult]):self.fn=fn
    def evaluate(self,response,diff=None):return self.fn(response,diff)
    def __and__(self,other):return Matcher(lambda r,d: MatchResult(self.evaluate(r,d).matched and other.evaluate(r,d).matched,"AND expression"))
    def __or__(self,other):return Matcher(lambda r,d: MatchResult(self.evaluate(r,d).matched or other.evaluate(r,d).matched,"OR expression"))
    def __invert__(self):return Matcher(lambda r,d: MatchResult(not self.evaluate(r,d).matched,"NOT expression"))

def status(*codes):return Matcher(lambda r,d:MatchResult(r.status in codes,f"status={r.status}"))
def header(name,pattern=None):
    return Matcher(lambda r,d:MatchResult(name.lower() in r.headers and (pattern is None or bool(re.search(pattern,r.headers.get(name.lower(),""),re.I))),f"header {name}"))
def text(value,regex=False):return Matcher(lambda r,d:MatchResult(bool(re.search(value,r.body.decode(errors='replace'),re.I)) if regex else value in r.body.decode(errors='replace'),f"text {value}"))
def length(minimum=0,maximum=None):return Matcher(lambda r,d:MatchResult(len(r.body)>=minimum and (maximum is None or len(r.body)<=maximum),f"length={len(r.body)}"))
def similarity(below=None,above=None):return Matcher(lambda r,d:MatchResult(d is not None and (below is None or d.similarity<below) and (above is None or d.similarity>above),f"similarity={d.similarity if d else 'n/a'}"))
def timing(minimum_ms):return Matcher(lambda r,d:MatchResult(r.elapsed_ms>=minimum_ms,f"elapsed={r.elapsed_ms}ms"))
def redirect():return Matcher(lambda r,d:MatchResult(300<=r.status<400 and bool(r.redirect_url),f"redirect={r.redirect_url}"))

def extract_regex(response:HttpResponse,pattern:str):return re.findall(pattern,response.body.decode(errors="replace"),re.I)
def extract_json_path(response:HttpResponse,path:str)->Any:
    value=json.loads(response.body);parts=[p for p in path.strip("$.").split(".") if p]
    for part in parts:value=value[int(part)] if isinstance(value,list) else value[part]
    return value
