import json
import re
from difflib import SequenceMatcher
from hashlib import sha256
from html.parser import HTMLParser
from .models import HttpResponse, ResponseDiff, ResponseSummary

VOLATILE = [
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[T ][0-9:.+Z-]+\b"), "<TIMESTAMP>"),
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f-]{27,}\b", re.I), "<UUID>"),
    (re.compile(r"\b[0-9a-f]{24,}\b", re.I), "<HEX>"),
    (re.compile(r'(?i)(csrf|nonce|token)(["\'\s:=]+)[A-Za-z0-9_./+-]{8,}'), r"\1\2<VOLATILE>"),
]

class StructureParser(HTMLParser):
    def __init__(self): super().__init__(); self.tags=[]
    def handle_starttag(self, tag, attrs): self.tags.append(tag.lower())

def normalize_text(body: bytes, content_type: str="") -> str:
    text=body.decode("utf-8",errors="replace")
    if "json" in content_type:
        try: text=json.dumps(json.loads(text),sort_keys=True,separators=(",",":"))
        except (ValueError,TypeError): pass
    for pattern,replacement in VOLATILE:text=pattern.sub(replacement,text)
    return re.sub(r"\s+"," ",text).strip()

def summarize(response: HttpResponse) -> ResponseSummary:
    normalized=normalize_text(response.body,response.headers.get("content-type",""));parser=StructureParser()
    if "html" in response.headers.get("content-type","") or normalized.startswith("<"):
        try: parser.feed(normalized)
        except Exception: pass
    return ResponseSummary(response.status,len(response.body),sha256(normalized.encode()).hexdigest(),normalized,parser.tags,response.elapsed_ms)

def compare(left: ResponseSummary,right: ResponseSummary,left_headers=None,right_headers=None) -> ResponseDiff:
    lh=set((left_headers or {}).keys());rh=set((right_headers or {}).keys())
    return ResponseDiff(round(SequenceMatcher(None,left.normalized_text,right.normalized_text).ratio(),4),left.status!=right.status,right.length-left.length,sorted(rh-lh),sorted(lh-rh),left.structure!=right.structure,right.elapsed_ms-left.elapsed_ms)

def baseline_stability(summaries: list[ResponseSummary]) -> float:
    if len(summaries)<2:return 1.0
    scores=[SequenceMatcher(None,summaries[i-1].normalized_text,summaries[i].normalized_text).ratio() for i in range(1,len(summaries))]
    return round(sum(scores)/len(scores),4)
