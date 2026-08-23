import pathlib,sys,tempfile,unittest
sys.path.insert(0,str(pathlib.Path(__file__).parents[1]/"scanner"))
from engine.matchers import header,status,text
from engine.models import HttpRequest,HttpResponse,InputPoint,ScanContext,ScanLimits,ScanMode
from engine.normalization import baseline_stability,compare,summarize
from engine.safety import SafetyController,ScopeViolation,redact_headers

def response(body=b"<html><body>Hello</body></html>",status_code=200):
    return HttpResponse(status_code,"https://example.com/",{"content-type":"text/html"},[],body,20)

class ModelTests(unittest.TestCase):
    def test_input_identifier_is_stable_and_location_specific(self):
        self.assertEqual(InputPoint("query","id","1").identifier,InputPoint("query","id","2").identifier)
        self.assertNotEqual(InputPoint("query","id","1").identifier,InputPoint("json","id","1").identifier)

class NormalizationTests(unittest.TestCase):
    def test_dynamic_values_are_normalized(self):
        a=summarize(response(b"<p>2026-08-23T10:11:12Z 550e8400-e29b-41d4-a716-446655440000</p>"))
        b=summarize(response(b"<p>2026-08-24T11:12:13Z 123e4567-e89b-12d3-a456-426614174000</p>"))
        self.assertEqual(a.normalized_hash,b.normalized_hash)
        self.assertEqual(1.0,baseline_stability([a,b]))
    def test_diff_detects_structural_and_status_change(self):
        left=summarize(response());right=summarize(response(b"<html><form></form></html>",403))
        result=compare(left,right)
        self.assertTrue(result.status_changed);self.assertTrue(result.structure_changed)

class MatcherTests(unittest.TestCase):
    def test_logical_matchers(self):
        item=response();item.headers["x-test"]="yes"
        self.assertTrue((status(200)&header("x-test")&~text("failure")).evaluate(item).matched)

class SafetyTests(unittest.TestCase):
    def test_redacts_secrets(self):
        clean=redact_headers({"Authorization":"Bearer very-secret-token","Accept":"text/html"})
        self.assertNotIn("very-secret-token",clean["Authorization"]);self.assertEqual("text/html",clean["Accept"])
    def test_external_redirect_host_is_blocked(self):
        context=ScanContext("https://example.com/",ScanMode.PASSIVE,ScanLimits())
        control=SafetyController(context)
        with self.assertRaises(ScopeViolation):control.validate_url("https://example.org/")

if __name__=="__main__":unittest.main()
