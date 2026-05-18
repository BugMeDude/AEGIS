from aegis.parsers import (parse_any, parse_curl, parse_curl_multi,
                            parse_har, parse_openapi, parse_postman)


def test_curl_basic():
    s = parse_curl("curl https://api.example.com/v1/users")
    assert s and s.method == "GET" and s.url.endswith("/v1/users")


def test_curl_full():
    cmd = ("curl -X POST 'https://api.x.com/login' "
           "-H 'Content-Type: application/json' "
           "--data-raw '{\"u\":\"a\"}'")
    s = parse_curl(cmd)
    assert s.method == "POST"
    assert s.headers["Content-Type"] == "application/json"
    assert s.body == '{"u":"a"}'


def test_curl_implicit_post_on_data():
    s = parse_curl("curl https://x.com/a -d 'k=v'")
    assert s.method == "POST" and s.body == "k=v"


def test_curl_get_form():
    s = parse_curl("curl -G https://x.com/s -d 'q=1'")
    assert s.method == "GET" and s.url.endswith("?q=1")


def test_curl_basic_auth():
    s = parse_curl("curl -u user:pass https://x.com")
    assert s.headers["Authorization"].startswith("Basic ")


def test_curl_multiline_continuation():
    blob = "curl https://x.com/a \\\n  -H 'A: 1' \\\n  -d 'b=2'"
    s = parse_curl(blob)
    assert s.headers["A"] == "1" and s.body == "b=2"


def test_curl_multi():
    blob = "curl https://a.com\ncurl https://b.com"
    specs = parse_curl_multi(blob)
    assert len(specs) == 2


def test_postman_recursive_with_vars():
    doc = {
        "variable": [{"key": "base", "value": "https://api.x.com"}],
        "item": [
            {"name": "folder", "item": [
                {"name": "get", "request": {
                    "method": "GET", "url": {"raw": "{{base}}/u"}}}]},
            {"name": "post", "request": {
                "method": "POST", "url": "{{base}}/p",
                "header": [{"key": "X", "value": "1"}],
                "body": {"mode": "raw", "raw": "{}"}}},
        ],
    }
    specs = parse_postman(doc)
    assert len(specs) == 2
    assert specs[0].url == "https://api.x.com/u"
    assert specs[1].headers["X"] == "1"


def test_openapi():
    doc = {"openapi": "3.0.0", "servers": [{"url": "https://api.x.com"}],
           "paths": {"/u": {"get": {"operationId": "listUsers"},
                            "post": {}}}}
    specs = parse_openapi(doc)
    assert len(specs) == 2
    assert any(s.method == "POST" and s.body == "{}" for s in specs)


def test_har():
    doc = {"log": {"entries": [{"request": {
        "method": "GET", "url": "https://x.com/a",
        "headers": [{"name": "Accept", "value": "*/*"},
                    {"name": ":authority", "value": "x.com"}]}}]}}
    specs = parse_har(doc)
    assert len(specs) == 1 and ":authority" not in specs[0].headers


def test_auto_detect():
    assert parse_any("curl https://x.com")[0].url == "https://x.com"
    assert parse_any("https://x.com/a\nhttps://x.com/b")
    assert len(parse_any("https://x.com/a\nhttps://x.com/b")) == 2


def test_global_overrides():
    specs = parse_any("curl https://old.com/path",
                      base_url="https://new.com", token="abc")
    assert specs[0].url == "https://new.com/path"
    assert specs[0].headers["Authorization"] == "Bearer abc"
