"""Crawling tests: the scanner must expand a single seed URL into the reachable same-origin
surface and test pages it was never handed directly, while staying read-only (never following
logout or state-changing links) and never leaving the authorized host."""
import pathlib
import sys
import unittest
import unittest.mock
from http.server import BaseHTTPRequestHandler

sys.path.insert(0, str(pathlib.Path(__file__).parent))
sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "scanner"))

from support.local_server import serve
from engine.crawler import (
    CrawlFrontier, extract_links, extract_script_sources, is_followable, page_shape, page_signature,
    page_structure, same_scope, same_template, urls_from_javascript,
)
from engine.runner import run_scan


class LinkExtractionTests(unittest.TestCase):
    def test_extracts_anchors_and_get_forms_absolutely(self):
        body = ('<a href="/a">a</a><a href="sub/b">b</a>'
                '<form method="get" action="/search"></form>'
                '<form method="post" action="/delete"></form>'
                '<a href="javascript:void(0)">x</a><a href="mailto:z@z">m</a>')
        links = extract_links("http://h/dir/page", body)
        self.assertIn("http://h/a", links)
        self.assertIn("http://h/dir/sub/b", links)
        self.assertIn("http://h/search", links)          # GET form action is navigable
        self.assertNotIn("http://h/delete", links)        # POST form action is not
        self.assertFalse([u for u in links if u.startswith(("javascript", "mailto"))])

    def test_is_followable_blocks_logout_destructive_and_assets(self):
        self.assertTrue(is_followable("http://h/products?id=1"))
        self.assertFalse(is_followable("http://h/account/logout"))
        self.assertFalse(is_followable("http://h/app?action=delete&id=3"))
        self.assertFalse(is_followable("http://h/item?remove=3"))
        self.assertFalse(is_followable("http://h/assets/app.js"))

    def test_page_signature_keeps_values_and_page_shape_ignores_them(self):
        # index.php?p=12 and ?p=14 are two screens of an app that routes by parameter.
        self.assertNotEqual(page_signature("http://h/index.php?p=12"), page_signature("http://h/index.php?p=14"))
        self.assertEqual(page_signature("http://h/p?a=1&b=2"), page_signature("http://h/p?b=2&a=1"))
        self.assertEqual(page_shape("http://h/p?id=1"), page_shape("http://h/p?id=2"))
        self.assertNotEqual(page_shape("http://h/p?id=1"), page_shape("http://h/p?cat=1"))

    def test_same_scope_pins_host_and_port(self):
        self.assertTrue(same_scope("http://h:80/x", "h", 80))
        self.assertFalse(same_scope("http://other/x", "h", 80))
        self.assertFalse(same_scope("http://h:8443/x", "h", 80))


class LinkedPage(BaseHTTPRequestHandler):
    """A login-style landing page that links to a *separate* page carrying a reflected-XSS
    parameter — the exact case the user described: the seed is a login screen, but an unlinked-
    from-nowhere-else vulnerable page sits one hop away and must be discovered and tested."""

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/login"):
            body = ('<html><body>Faça login. '
                    '<a href="/search?q=hello">Buscar</a> '
                    '<a href="/logout">Sair</a></body></html>')
        elif self.path.startswith("/search"):
            from urllib.parse import parse_qs, urlparse
            q = parse_qs(urlparse(self.path).query).get("q", [""])[0]
            body = f"<html><body>Resultado: {q}</body></html>"   # reflected unescaped
        else:
            body = "<html><body>404</body></html>"
        raw = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *args):
        pass


class CrawlReachTests(unittest.TestCase):
    def test_scan_discovers_and_tests_a_linked_page(self):
        with serve(LinkedPage) as base_url:
            result = run_scan(base_url + "/login", mode="safe_active", allow_private=True,
                              max_pages=10, max_depth=2)
        self.assertTrue(result["ok"])
        self.assertGreaterEqual(result["pages_scanned"], 2)
        self.assertTrue(any("/search" in u for u in result["crawled_urls"]),
                        "crawler should have reached /search from the seed")
        self.assertNotIn(base_url + "/logout", result["crawled_urls"])  # logout never followed
        xss = [f for f in result["findings"] if f["fingerprint"].startswith("xss.")]
        self.assertTrue(xss, "reflected XSS on the discovered /search page should be flagged")
        self.assertTrue(any("/search" in f["affected_url"] for f in xss))

    def test_single_page_scan_when_crawl_disabled(self):
        with serve(LinkedPage) as base_url:
            result = run_scan(base_url + "/login", mode="safe_active", allow_private=True,
                              max_pages=1)
        self.assertTrue(result["ok"])
        self.assertEqual(1, result["pages_scanned"])
        self.assertEqual([], [f for f in result["findings"] if f["fingerprint"].startswith("xss.")])

    def test_transient_network_failure_midscan_preserves_findings(self):
        """A timeout while probing a later page must not discard the whole scan: the seed page's
        findings survive and the scan still reports ok."""
        from engine.transport import HttpTransport
        real_send = HttpTransport.send

        def flaky_send(self, request):
            if "/search" in request.url:      # the discovered second page times out mid-crawl
                raise TimeoutError("simulated network timeout")
            return real_send(self, request)

        with serve(LinkedPage) as base_url:
            with unittest.mock.patch.object(HttpTransport, "send", flaky_send):
                result = run_scan(base_url + "/login", mode="passive", allow_private=True,
                                  max_pages=10, max_depth=2)
        self.assertTrue(result["ok"], "a transient timeout must not fail the whole scan")
        self.assertGreaterEqual(result["pages_scanned"], 1)
        self.assertTrue(result["findings"], "seed-page findings must be preserved")


class JavaScriptDiscoveryTests(unittest.TestCase):
    def test_inline_scripts_handlers_and_data_attributes_are_read(self):
        body = ('<button onclick="location.href=\'index.php?p=9\'">Ir</button>'
                '<tr data-href="pedido.php?id=4"></tr>'
                '<script>fetch(`api/itens.php?q=${termo}`); const cls = "btn btn-primary";</script>')
        links = extract_links("http://h/app/index.php?p=1", body)
        self.assertIn("http://h/app/index.php?p=9", links)
        self.assertIn("http://h/app/pedido.php?id=4", links)
        self.assertIn("http://h/app/api/itens.php?q=1", links)   # runtime value becomes 1
        self.assertFalse([u for u in links if "btn" in u])          # plain strings are not URLs

    def test_urls_from_javascript_resolves_against_the_page(self):
        source = ("$.get('web/endpoint/ep_motor.php?detalhe=' + matnr);"
                  "fetch(`web/endpoint/ep_list.php?${params}`);"
                  "axios.get('/api/v1/orders');"
                  "const img = 'logo.png'; const msg = 'Salvo com sucesso';")
        urls = urls_from_javascript("http://h/portal/index.php?p=3", source)
        self.assertIn("http://h/portal/web/endpoint/ep_motor.php?detalhe=1", urls)
        self.assertIn("http://h/portal/web/endpoint/ep_list.php", urls)  # `?${params}` has no name
        self.assertIn("http://h/api/v1/orders", urls)
        self.assertFalse([u for u in urls if u.endswith("logo.png") or "Salvo" in u])

    def test_script_sources_skip_well_known_libraries(self):
        body = ('<script src="js/jquery-3.7.1.min.js"></script>'
                '<script src="assets/js/pedidos.js?v=2"></script>')
        self.assertEqual(["http://h/assets/js/pedidos.js?v=2"], extract_script_sources("http://h/", body))

    def test_destructive_path_segments_are_never_followed(self):
        self.assertFalse(is_followable("http://h/web/endpoint/delete_user_ajax.php"))
        self.assertFalse(is_followable("http://h/user/delete/5"))
        self.assertFalse(is_followable("http://h/pedido/excluir?id=3"))
        self.assertTrue(is_followable("http://h/relatorios/deletados"))   # a word, not an action


def _screen(title: str, content: str) -> str:
    """A page of a back-office application: big shared sidebar, small screen-specific body."""
    sidebar = "".join(f"<li><a class='nav-link' href='index.php?p={n}'><i class='fa'></i><span>Tela {n}</span></a></li>"
                      for n in range(1, 21))
    return (f"<html><head><title>Portal</title></head><body><nav><ul>{sidebar}</ul></nav>"
            f"<main><h1>{title}</h1>{content}</main></body></html>")


class TemplateRecognitionTests(unittest.TestCase):
    def test_records_shown_by_one_template_are_the_same_template(self):
        def product(n: int, reviews: int) -> str:
            return _screen(f"Produto {n}", f"<p>R$ {n},90</p><label>Quantidade</label><input name='qtd'>"
                                           "<button>Comprar</button>" + "<p>avaliação</p>" * reviews)
        self.assertTrue(same_template(page_structure(product(1, 2)), page_structure(product(2, 4))))

    def test_two_screens_sharing_a_sidebar_are_not_the_same_template(self):
        invoices = _screen("Notas", "<button>Emitidas</button><table><tr><th>Nº Nota</th></tr></table>")
        receipts = _screen("Comprovantes", "<button>Todos</button><table><tr><th>Nº Documento</th></tr></table>")
        self.assertFalse(same_template(page_structure(invoices), page_structure(receipts)))

    def test_screens_without_labels_need_a_practically_identical_layout(self):
        home = _screen("Início", "<div class='card'><h6>Precisa de ajuda?</h6></div>")
        about = _screen("Sobre", "<section><p>Texto</p><p>Mais texto</p><ul><li>a</li></ul></section>")
        self.assertFalse(same_template(page_structure(home), page_structure(about)))

    def test_frontier_visits_new_shapes_first_and_stops_at_a_template(self):
        frontier = CrawlFrontier("http://h/loja", max_depth=3, duplicate_budget=30)
        self.assertEqual(("http://h/loja", 0), frontier.pop())
        for n in range(1, 11):
            frontier.offer(f"http://h/produto?id={n}", 1)
        frontier.offer("http://h/sobre", 1)
        order = [frontier.pop()[0], frontier.pop()[0]]
        self.assertEqual(["http://h/produto?id=1", "http://h/sobre"], order)  # new shapes first
        page = page_structure(_screen("P", "<button>Comprar</button>"))
        self.assertFalse(frontier.repeats_template("http://h/produto?id=1", page))
        repeats = []
        while (next_page := frontier.pop()) is not None:
            repeats.append(frontier.repeats_template(next_page[0], page))
        self.assertEqual([True, True, True], repeats)        # three repeats, then the shape is done
        self.assertEqual([], frontier.not_visited())          # template variants are not "missed"
        self.assertEqual(9, frontier.template_variants_skipped)

    def test_variants_skipped_for_lack_of_budget_are_reported_as_not_visited(self):
        frontier = CrawlFrontier("http://h/index.php?p=1", max_depth=3, duplicate_budget=1)
        frontier.pop()
        frontier.repeats_template("http://h/index.php?p=1", page_structure(_screen("A", "<button>A</button>")))
        for n in (2, 3, 4):
            frontier.offer(f"http://h/index.php?p={n}", 1)
        url, _ = frontier.pop()
        self.assertTrue(frontier.repeats_template(url, page_structure(_screen("A", "<button>A</button>"))))
        self.assertIsNone(frontier.pop())                     # the repeat budget is spent...
        self.assertEqual(["http://h/index.php?p=3", "http://h/index.php?p=4"], frontier.not_visited())
        self.assertEqual(1, frontier.template_variants_skipped)  # ...and only the real repeat is counted


class PortalLike(BaseHTTPRequestHandler):
    """An application that routes by parameter (`index.php?p=N`), like a PHP back office: every
    screen shares one sidebar, a vulnerable form exists only on screen 4, and screen 5 loads a
    script whose AJAX endpoint reflects its parameter — reachable only through that script."""

    requested: list[str] = []
    SCREENS = {
        "1": ("Início", "<div class='card'><h6>Precisa de ajuda?</h6></div>"),
        "2": ("Notas Fiscais", "<button>Emitidas</button><button>Denegadas</button>"
                               "<table><tr><th>Nº Nota</th><th>Emissão</th></tr></table>"),
        "3": ("Comprovantes", "<button>Últimos 30 dias</button><table><tr><th>Nº Documento</th></tr></table>"),
        "4": ("Motores", "<form method='post'><label>Buscar motor</label><input name='motor'>"
                         "<button>Buscar</button></form>"),
        "5": ("Pedidos", "<script src='assets/js/pedidos.js'></script><table><tr><th>Pedido</th></tr></table>"),
    }

    def _send(self, body: str, content_type: str = "text/html; charset=utf-8") -> None:
        raw = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _screen_body(self, number: str, extra: str = "") -> str:
        title, content = self.SCREENS.get(number, ("Não encontrado", ""))
        sidebar = "".join(f"<li><a href='index.php?p={n}'><i></i><span>{t}</span></a></li>"
                          for n, (t, _) in self.SCREENS.items())
        sidebar += "<li><a href='logout.php'>Sair</a></li><li><a href='index.php?p=2&action=delete'>x</a></li>"
        return f"<html><body><nav><ul>{sidebar}</ul></nav><main><h1>{title}</h1>{content}{extra}</main></body></html>"

    def do_GET(self):
        from urllib.parse import parse_qs, urlparse
        PortalLike.requested.append(self.path)
        url = urlparse(self.path)
        query = parse_qs(url.query)
        if url.path == "/assets/js/pedidos.js":
            self._send("function buscar(q){ return fetch(`web/endpoint/ep_pedidos.php?busca=${encodeURIComponent(q)}`); }\n"
                       "function excluir(id){ $.post('web/endpoint/delete_pedido_ajax.php', {id: id}); }\n"
                       "const classe = 'btn btn-danger';", "application/javascript")
        elif url.path == "/web/endpoint/ep_pedidos.php":
            self._send(f"<html><body><p>Resultado para {query.get('busca', [''])[0]}</p></body></html>")
        else:
            self._send(self._screen_body(query.get("p", ["1"])[0]))

    def do_POST(self):
        from urllib.parse import parse_qs, urlparse
        PortalLike.requested.append("POST " + self.path)
        length = int(self.headers.get("Content-Length") or 0)
        fields = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
        number = parse_qs(urlparse(self.path).query).get("p", ["1"])[0]
        extra = f"<p>Motor: {fields.get('motor', [''])[0]}</p>" if number == "4" else ""   # unescaped
        self._send(self._screen_body(number, extra))

    def log_message(self, *args):
        pass


class Catalog(BaseHTTPRequestHandler):
    """A shop: one listing linking to 40 products rendered by the same template."""

    requested: list[str] = []

    def do_GET(self):
        from urllib.parse import parse_qs, urlparse
        Catalog.requested.append(self.path)
        url = urlparse(self.path)
        if url.path == "/produto":
            n = int(parse_qs(url.query).get("id", ["1"])[0])
            related = "".join(f"<a href='/produto?id={(n + k) % 40 + 1}'>Veja também</a>" for k in range(3))
            body = (f"<html><body><h1>Produto {n}</h1><p>R$ {n},90 — descrição do produto {n}</p>"
                    "<form method='post' action='/carrinho'><label>Quantidade</label><input name='qtd'>"
                    f"<button>Comprar</button></form>{related}</body></html>")
        else:
            body = "<html><body>" + "".join(f"<a href='/produto?id={n}'>Produto {n}</a>" for n in range(1, 41)) + "</body></html>"
        raw = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *args):
        pass


class SmartCrawlTests(unittest.TestCase):
    def test_every_screen_of_a_parameter_routed_app_is_analysed(self):
        PortalLike.requested = []
        with serve(PortalLike) as base_url:
            result = run_scan(base_url + "/index.php?p=1", mode="safe_active", allow_private=True,
                              max_pages=20, max_depth=2)
        self.assertTrue(result["ok"])
        crawled = result["crawled_urls"]
        for number in PortalLike.SCREENS:
            self.assertIn(f"{base_url}/index.php?p={number}", crawled, f"screen p={number} was not analysed")
        self.assertIn(f"{base_url}/web/endpoint/ep_pedidos.php?busca=1", crawled,
                      "the AJAX endpoint called by pedidos.js was not discovered")
        self.assertEqual(1, result["scripts_read"])

        xss = [f for f in result["findings"] if f["fingerprint"].startswith("xss.")]
        self.assertTrue(any(f["parameter"] == "motor" for f in xss), "XSS in the screen-4 form was missed")
        self.assertTrue(any(f["parameter"] == "busca" for f in xss), "XSS in the AJAX endpoint was missed")

        requested = " ".join(PortalLike.requested)
        self.assertNotIn("logout.php", requested)
        self.assertNotIn("delete_pedido_ajax", requested)
        self.assertNotIn("action=delete", requested)

    def test_a_catalog_costs_only_a_few_requests(self):
        Catalog.requested = []
        with serve(Catalog) as base_url:
            result = run_scan(base_url + "/", mode="passive", allow_private=True, max_pages=30, max_depth=3)
        self.assertTrue(result["ok"])
        products = [u for u in result["crawled_urls"] if "/produto" in u]
        self.assertEqual(1, len(products), "one product page is enough to cover the template")
        self.assertGreaterEqual(result["template_variants_skipped"], 30)
        self.assertEqual(0, result["pages_not_visited"])
        product_requests = [p for p in Catalog.requested if p.startswith("/produto")]
        self.assertLessEqual(len(product_requests), 5, "2 baselines + 3 repeats of the template at most")

    def test_pages_left_out_by_the_page_limit_are_reported(self):
        PortalLike.requested = []
        with serve(PortalLike) as base_url:
            result = run_scan(base_url + "/index.php?p=1", mode="passive", allow_private=True, max_pages=3)
        self.assertTrue(result["ok"])
        self.assertEqual(3, result["pages_scanned"])
        self.assertGreaterEqual(result["pages_not_visited"], 2)
        self.assertTrue(all(u.startswith(base_url) for u in result["not_visited_urls"]))
        self.assertFalse(set(result["not_visited_urls"]) & set(result["crawled_urls"]))


if __name__ == "__main__":
    unittest.main()
