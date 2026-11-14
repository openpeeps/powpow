## tests/test_client_policy.nim — H1 client policy (Phase 1B, part 1):
## redirect following (B1) + cookie jar (B2).

import std/httpcore except HttpMethod
import std/[strutils, unittest]
import ../src/powpow

# ── Pure URL resolution units ────────────────────────────────────────────────

test "redirect_resolve_absolute":
  check resolveRedirectUrl("http://a:8080/x/y", "https://b.com/z") ==
    "https://b.com/z"

test "redirect_resolve_rooted":
  check resolveRedirectUrl("http://a:8080/x/y", "/new") ==
    "http://a:8080/new"

test "redirect_resolve_relative":
  check resolveRedirectUrl("http://a:8080/x/y", "sub") == "http://a:8080/x/sub"
  check resolveRedirectUrl("http://a:8080/x/y", "../up") == "http://a:8080/x/../up"

test "redirect_resolve_query_and_scheme_relative":
  check resolveRedirectUrl("http://a:8080/x/y?q=1", "?q=2") ==
    "http://a:8080/x/y?q=2"
  check resolveRedirectUrl("http://a:8080/x/y", "//b.com/z") ==
    "http://b.com/z"

test "redirect_resolve_default_port_omitted":
  check resolveRedirectUrl("http://a/x", "/n") == "http://a/n"
  check resolveRedirectUrl("https://a:443/x", "/n") == "https://a/n"

test "redirect_resolve_empty_and_fragment":
  check resolveRedirectUrl("http://a/x", "") == ""
  check resolveRedirectUrl("http://a/x", "#frag") == ""
  check resolveRedirectUrl("http://a/x?old=1", "/n#frag") == "http://a/n"

# ── Cookie jar units (fabricated responses) ──────────────────────────────────

proc fakeResponse(headers: openArray[(string, string)]): HttpClientResponse =
  var raw = "HTTP/1.1 200 OK\r\n"
  for (k, v) in headers:
    raw.add(k & ": " & v & "\r\n")
  raw.add("\r\n")
  let p = newHttpParser()
  p.responseMode = true
  discard p.feed(raw)
  doAssert p.isComplete()
  HttpClientResponse(parser: p)

test "jar_basic_store_and_send":
  let jar = newCookieJar()
  jar.storeResponseCookies("http://example.com/",
    fakeResponse([("Set-Cookie", "a=1; Path=/"), ("Set-Cookie", "b=2; Path=/")]))
  check jar.cookieHeaderForUrl("http://example.com/") == "a=1; b=2"
  check jar.cookieHeaderForUrl("http://other.com/") == ""

test "jar_domain_scope":
  let jar = newCookieJar()
  jar.storeResponseCookies("http://example.com/",
    fakeResponse([("Set-Cookie", "a=1; Domain=example.com")]))
  check jar.cookieHeaderForUrl("http://example.com/") == "a=1"
  check jar.cookieHeaderForUrl("http://sub.example.com/") == "a=1"
  check jar.cookieHeaderForUrl("http://other.com/") == ""
  # Reject cookies for unrelated domains.
  jar.storeResponseCookies("http://example.com/",
    fakeResponse([("Set-Cookie", "evil=1; Domain=other.com")]))
  check "evil" notin jar.cookieHeaderForUrl("http://other.com/")

test "jar_host_only":
  let jar = newCookieJar()
  jar.storeResponseCookies("http://example.com/",
    fakeResponse([("Set-Cookie", "h=1")]))
  check jar.cookieHeaderForUrl("http://example.com/") == "h=1"
  check jar.cookieHeaderForUrl("http://sub.example.com/") == ""

test "jar_path_scope":
  let jar = newCookieJar()
  jar.storeResponseCookies("http://example.com/dir/page",
    fakeResponse([("Set-Cookie", "p=1")]))
  check jar.cookieHeaderForUrl("http://example.com/dir/other") == "p=1"
  check jar.cookieHeaderForUrl("http://example.com/other") == ""

test "jar_secure_and_expiry":
  let jar = newCookieJar()
  jar.storeResponseCookies("https://example.com/",
    fakeResponse([("Set-Cookie", "s=1; Secure"), ("Set-Cookie", "gone=1"),
                  ("Set-Cookie", "gone=2; Max-Age=0")]))
  check jar.cookieHeaderForUrl("https://example.com/") == "s=1"
  check jar.cookieHeaderForUrl("http://example.com/") == ""

# ── Live redirect tests ──────────────────────────────────────────────────────

test "redirect_basic_and_disabled_by_default":
  let client = newHttpClient(maxRedirects = 3)
  let server = newHttpServer(client.getLoop())
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    if req.getPath() == "/old":
      res.status(Http301).header("Location", "/new").send("")
    else:
      res.status(Http200).send("new-body")
  server.listen("127.0.0.1", 19880)

  let r = client.get("http://127.0.0.1:19880/old")
  check r.getStatusCode() == Http200
  check r.getBodyString() == "new-body"

  client.maxRedirects = 0
  let r2 = client.get("http://127.0.0.1:19880/old")
  check r2.getStatusCode() == Http301

  server.close()
  client.close()

test "redirect_post_rewrite_and_307_keep":
  let client = newHttpClient(maxRedirects = 3)
  let server = newHttpServer(client.getLoop())
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    {.gcsafe.}:
      if req.getPath() == "/old302":
        res.status(Http302).header("Location", "/new").send("")
      elif req.getPath() == "/old307":
        res.status(Http307).header("Location", "/new").send("")
      else:
        let m = $req.getMethod()
        res.status(Http200).send(m & "|" & req.getBodyString())
  server.listen("127.0.0.1", 19881)

  let a = client.post("http://127.0.0.1:19881/old302", "data")
  check a.getBodyString() == "GET|"
  let b = client.post("http://127.0.0.1:19881/old307", "data")
  check b.getBodyString() == "POST|data"

  server.close()
  client.close()

test "redirect_loop_capped":
  let client = newHttpClient(maxRedirects = 2)
  let server = newHttpServer(client.getLoop())
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    res.status(Http302).header("Location", "/loop").send("")
  server.listen("127.0.0.1", 19882)

  let r = client.get("http://127.0.0.1:19882/loop")
  check r.getStatusCode() == Http302
  check r.getHeaderValue("location") == "/loop"

  server.close()
  client.close()

test "redirect_bad_location_errors":
  let client = newHttpClient(maxRedirects = 3)
  let server = newHttpServer(client.getLoop())
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    res.status(Http302).header("Location", "http://[::1").send("")
  server.listen("127.0.0.1", 19883)

  var raised = false
  try:
    discard client.get("http://127.0.0.1:19883/bad")
  except HttpError:
    raised = true
  check raised

  server.close()
  client.close()

test "redirect_cross_origin_strips_auth":
  let client = newHttpClient(maxRedirects = 3)
  let server = newHttpServer(client.getLoop())
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    {.gcsafe.}:
      if req.getPath() == "/go":
        res.status(Http302)
          .header("Location", "http://127.0.0.1:19885/land")
          .send("")
      elif req.getPath() == "/land":
        res.status(Http200).send("auth=" & req.getHeaderValue("authorization"))
      else:
        res.sendError(Http404, "nope")
  server.listen("127.0.0.1", 19884)
  let serverB = newHttpServer(client.getLoop())
  serverB.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    {.gcsafe.}:
      res.status(Http200).send("auth=" & req.getHeaderValue("authorization"))
  serverB.listen("127.0.0.1", 19885)

  let r = client.get("http://127.0.0.1:19884/go",
                     [("Authorization", "Bearer secret")])
  # Same host, different port: cross-origin for credentials.
  check r.getBodyString() == "auth="

  server.close()
  serverB.close()
  client.close()

# ── Live cookie tests ────────────────────────────────────────────────────────

test "cookies_live_roundtrip":
  let client = newHttpClient()
  client.cookieJar = newCookieJar()
  let server = newHttpServer(client.getLoop())
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    {.gcsafe.}:
      if req.getPath() == "/set":
        res.status(Http200)
          .header("Set-Cookie", "a=1; Path=/")
          .header("Set-Cookie", "b=2; Path=/")
          .send("set")
      else:
        let c = req.getHeaderValue("cookie")
        res.status(Http200).send(if c.len > 0: c else: "none")
  server.listen("127.0.0.1", 19886)

  discard client.get("http://127.0.0.1:19886/set")
  let echoRes = client.get("http://127.0.0.1:19886/echo")
  check echoRes.getBodyString() == "a=1; b=2"

  client.cookieJar = nil
  let echoPlain = client.get("http://127.0.0.1:19886/echo")
  check echoPlain.getBodyString() == "none"

  server.close()
  client.close()

test "cookies_live_path_scope":
  let client = newHttpClient()
  client.cookieJar = newCookieJar()
  let server = newHttpServer(client.getLoop())
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    {.gcsafe.}:
      if req.getPath() == "/set":
        res.status(Http200)
          .header("Set-Cookie", "p=1; Path=/sub")
          .send("set")
      else:
        let c = req.getHeaderValue("cookie")
        res.status(Http200).send(if c.len > 0: c else: "none")
  server.listen("127.0.0.1", 19887)

  discard client.get("http://127.0.0.1:19887/set")
  check client.get("http://127.0.0.1:19887/sub/x").getBodyString() == "p=1"
  check client.get("http://127.0.0.1:19887/other").getBodyString() == "none"

  server.close()
  client.close()

test "cookies_live_redirect_carry":
  let client = newHttpClient(maxRedirects = 3)
  client.cookieJar = newCookieJar()
  let server = newHttpServer(client.getLoop())
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    {.gcsafe.}:
      if req.getPath() == "/login":
        res.status(Http302)
          .header("Location", "/home")
          .header("Set-Cookie", "sess=abc; Path=/")
          .send("")
      else:
        let c = req.getHeaderValue("cookie")
        res.status(Http200).send(if c.len > 0: c else: "none")
  server.listen("127.0.0.1", 19888)

  let r = client.get("http://127.0.0.1:19888/login")
  check r.getStatusCode() == Http200
  check r.getBodyString() == "sess=abc"

  server.close()
  client.close()
