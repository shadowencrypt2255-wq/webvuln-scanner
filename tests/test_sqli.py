import requests_mock

from scanner.sqli import test_url_params as run_sqli_url_params


def test_detects_error_based_sqli():
    url = "http://example.test/search?q=widgets"
    with requests_mock.Mocker() as m:
        def responder(request, context):
            if "'" in request.qs.get("q", [""])[0]:
                return "you have an error in your sql syntax near..."
            return "no error here"

        m.get(requests_mock.ANY, text=responder)
        import requests
        findings = run_sqli_url_params(url, requests.Session())

    assert any(f.category == "SQL Injection" for f in findings)


def test_no_findings_on_clean_target():
    url = "http://example.test/search?q=widgets"
    with requests_mock.Mocker() as m:
        m.get(requests_mock.ANY, text="all good, no errors")
        import requests
        findings = run_sqli_url_params(url, requests.Session())

    assert findings == []
