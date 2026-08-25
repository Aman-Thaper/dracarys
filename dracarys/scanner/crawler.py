"""Lightweight crawler — discovers the attack surface of an arbitrary target.

Uses only the stdlib HTML parser. Extracts links (to crawl), forms (as request
templates with injection points), and query parameters, and imports an OpenAPI
schema if one is exposed. Stays within the scope enforced by the policy engine.
"""
from __future__ import annotations

import json
from collections import deque
from html.parser import HTMLParser
from urllib.parse import parse_qs, urljoin, urlparse, urlsplit

from dracarys.scanner.models import InjectionPoint, RequestTemplate, ScanContext
from dracarys.tools.base import HttpExchange


class _LinkFormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.forms: list[dict] = []
        self._cur: dict | None = None

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == "a" and d.get("href"):
            self.links.append(d["href"])
        elif tag == "form":
            self._cur = {"action": d.get("action", ""),
                         "method": (d.get("method") or "GET").upper(), "inputs": []}
        elif tag in ("input", "textarea", "select") and self._cur is not None:
            name = d.get("name")
            if name and d.get("type", "text") not in ("submit", "button", "image"):
                self._cur["inputs"].append((name, d.get("value", "test")))

    def handle_endtag(self, tag):
        if tag == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None


class Crawler:
    def __init__(self, ctx: ScanContext) -> None:
        self.ctx = ctx
        self.base = ctx.base_url
        self.host = urlparse(ctx.base_url).netloc
        self.seen_urls: set[str] = set()
        self.templates: dict[str, RequestTemplate] = {}
        self.baselines: list[tuple[str, HttpExchange]] = []

    def _in_scope(self, url: str) -> bool:
        p = urlparse(url)
        return p.scheme in ("http", "https") and p.netloc == self.host

    def _add_template(self, t: RequestTemplate) -> None:
        self.templates.setdefault(t.key(), t)

    def _template_from_url(self, url: str) -> None:
        parts = urlsplit(url)
        q = {k: (v[0] if v else "") for k, v in parse_qs(parts.query).items()}
        if not q:
            return
        clean = f"{parts.scheme}://{parts.netloc}{parts.path}"
        self._add_template(RequestTemplate(
            method="GET", url=clean, params=q, body_kind="query",
            injection_points=[InjectionPoint("query", k) for k in q],
            source="crawl-query",
        ))

    def _template_from_form(self, page_url: str, form: dict) -> None:
        action = urljoin(page_url, form["action"] or page_url)
        if not self._in_scope(action):
            return
        params = {name: (val or "test") for name, val in form["inputs"]}
        if not params:
            return
        method = form["method"] if form["method"] in ("GET", "POST") else "GET"
        self._add_template(RequestTemplate(
            method=method, url=action.split("?")[0], params=params,
            body_kind="form" if method == "POST" else "query",
            injection_points=[InjectionPoint("form", n) for n in params],
            source="crawl-form",
        ))

    async def crawl(self):
        cfg = self.ctx.config
        queue: deque[tuple[str, int]] = deque([(self.base, 0)])
        while queue and len(self.seen_urls) < cfg.max_pages:
            url, depth = queue.popleft()
            norm = url.split("#")[0]
            if norm in self.seen_urls or depth > cfg.max_depth or not self._in_scope(norm):
                continue
            self.seen_urls.add(norm)
            ex = await self.ctx.tool.send("GET", norm, headers=cfg.auth_headers,
                                          note=f"crawl {norm}")
            self.baselines.append((norm, ex))
            self._template_from_url(norm)
            ctype = (ex.response.get("headers", {}) or {}).get("content-type", "")
            if "html" not in ctype.lower():
                continue
            parser = _LinkFormParser()
            try:
                parser.feed(ex.body_text)
            except Exception:  # noqa: BLE001  malformed HTML is fine
                pass
            for form in parser.forms:
                self._template_from_form(norm, form)
            for href in parser.links:
                nxt = urljoin(norm, href).split("#")[0]
                if self._in_scope(nxt) and nxt not in self.seen_urls:
                    queue.append((nxt, depth + 1))

        await self._import_openapi()
        return list(self.templates.values()), self.baselines

    async def _import_openapi(self):
        for path in ("/openapi.json", "/swagger.json", "/api/openapi.json"):
            ex = await self.ctx.tool.send("GET", urljoin(self.base + "/", path.lstrip("/")),
                                          headers=self.ctx.config.auth_headers,
                                          note=f"import schema {path}")
            if ex.status_code != 200:
                continue
            try:
                spec = json.loads(ex.body_text)
            except (ValueError, TypeError):
                continue
            paths = spec.get("paths") if isinstance(spec, dict) else None
            if not isinstance(paths, dict):
                continue
            for p, ops in paths.items():
                if not isinstance(ops, dict) or "get" not in ops:
                    continue
                op = ops["get"]
                query, points = {}, []
                for prm in op.get("parameters", []) or []:
                    if prm.get("in") == "query":
                        schema = prm.get("schema") or {}
                        seed = schema.get("default") or prm.get("example") or schema.get("example") or "1"
                        query[prm["name"]] = str(seed)
                        points.append(InjectionPoint("query", prm["name"]))
                    elif prm.get("in") == "path":
                        points.append(InjectionPoint("path", prm["name"]))
                url = urljoin(self.base + "/", p.lstrip("/")).replace("{", "{").split("?")[0]
                # substitute path params with a probe value in the base url
                for prm in op.get("parameters", []) or []:
                    if prm.get("in") == "path":
                        url = url.replace(f"{{{prm['name']}}}", "1")
                self._add_template(RequestTemplate(
                    method="GET", url=url, params=query, body_kind="query",
                    injection_points=points, source="openapi",
                ))
            break
