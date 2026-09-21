import requests
import requests_mock

from scanner.crawler import Crawler

PAGE_1 = """
<html><body>
<a href="/page2">next</a>
<form action="/login" method="post">
  <input name="username">
  <input name="password" type="password">
</form>
</body></html>
"""

PAGE_2 = "<html><body>no links here</body></html>"


def test_crawler_discovers_pages_and_forms():
    with requests_mock.Mocker() as m:
        m.get("http://example.test/", text=PAGE_1, headers={"Content-Type": "text/html"})
        m.get("http://example.test/page2", text=PAGE_2, headers={"Content-Type": "text/html"})

        crawler = Crawler("http://example.test/", max_pages=10, session=requests.Session())
        result = crawler.crawl()

    assert "http://example.test/" in result.pages
    assert "http://example.test/page2" in result.pages
    assert len(result.forms) == 1
    assert result.forms[0].method == "post"
    assert {i["name"] for i in result.forms[0].inputs} == {"username", "password"}
