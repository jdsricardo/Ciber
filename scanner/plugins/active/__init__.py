"""Safe-active plugins: bounded, non-destructive probes against discovered parameters.

Each module here owns one vulnerability class end to end (its own reference-text
catalog, discovery, probing, control probes, and confirmation) so the classes stay
independently maintainable as the scanner grows. See scanner/plugins/*.py (passive)
for the shared conventions these follow: ScannerPlugin subclass, build_finding from
plugins.support, ConfidenceInputs from engine.confidence.
"""
