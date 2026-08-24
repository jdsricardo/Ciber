from abc import ABC,abstractmethod
from dataclasses import dataclass
from engine.models import Finding,HttpRequest,HttpResponse,ScanContext
from engine.transport import HttpTransport

@dataclass(frozen=True)
class PluginMetadata:
    name:str;category:str;cwe:str;owasp:str;wstg:str;kind:str;risk:str
    checks:tuple[str,...]=()

class ScannerPlugin(ABC):
    """kind is 'passive' (baseline-only, never sends extra requests) or 'safe_active'
    (may use `transport` to send additional, budget- and scope-controlled requests).
    `transport` is None for passive-only scans; safe_active plugins must not assume
    it is present without checking, so a plugin can be exercised in either mode."""
    metadata:PluginMetadata
    @abstractmethod
    def analyze(self,request:HttpRequest,responses:list[HttpResponse],context:ScanContext,transport:HttpTransport|None=None)->list[Finding]:...
