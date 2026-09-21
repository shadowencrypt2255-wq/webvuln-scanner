import requests
import requests_mock

from scanner.xss import test_url_params


def test_detects_reflected_xss():
    url = "http://example.test/comment?text=hello"
    with requests_mock.Mocker() as m:
        def responder(request, context):
            text = request.qs.get("text", [""])[0]
            return f"<div>{text}</div>"

        m.get(requests_mock.ANY, text=responder)
        findings = test_url_params(url, requests.Session())

    assert any(f.category.startswith("Cross-Site Scripting") for f in findings)


def test_no_findings_when_escaped():
    url = "http://example.test/comment?text=hello"
    with requests_mock.Mocker() as m:
        m.get(requests_mock.ANY, text="<div>&lt;script&gt;escaped&lt;/script&gt;</div>")
        findings = test_url_params(url, requests.Session())

    assert findings == []
