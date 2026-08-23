from abc import ABC,abstractmethod
from dataclasses import dataclass
from engine.models import Finding,HttpRequest,HttpResponse,ScanContext

@dataclass(frozen=True)
class PluginMetadata:
    name:str;category:str;cwe:str;owasp:str;wstg:str;kind:str;risk:str

class ScannerPlugin(ABC):
    metadata:PluginMetadata
    @abstractmethod
    def analyze(self,request:HttpRequest,responses:list[HttpResponse],context:ScanContext)->list[Finding]:...
