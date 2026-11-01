from sensors.log_parser import parse_line
from sensors.rules import Detector


def entry(path, ua="curl/8.5.0", status=200, ip="203.0.113.7"):
    line = f'{ip} - - [31/Oct/2026:09:00:00 +0000] "GET {path} HTTP/1.1" {status} 512 "-" "{ua}"'
    e = parse_line(line)
    assert e is not None
    return e


def names(path, **kw):
    return {d.rule_name for d in Detector().check(entry(path, **kw))}


def test_parses_combined_log():
    e = entry("/index.php?x=1", status=404)
    assert (e.ip, e.status, e.path) == ("203.0.113.7", 404, "/index.php?x=1")


def test_malformed_line_is_ignored():
    assert parse_line("this is not a log line") is None


def test_normal_requests_are_clean():
    assert names("/index.php") == set()
    assert names("/vulnerabilities/sqli/?id=1&Submit=Submit") == set()


def test_sqli():
    assert "SQL injection attempt" in names(
        "/vulnerabilities/sqli/?id=1%27%20UNION%20SELECT%20user,password%20FROM%20users--%20")


def test_double_encoded_sqli():
    assert "SQL injection attempt" in names("/?id=1%2527%2520OR%25201%253D1")


def test_xss():
    assert "Cross-site scripting attempt" in names(
        "/vulnerabilities/xss_r/?name=%3Cscript%3Ealert(1)%3C/script%3E")


def test_path_traversal():
    assert "Path traversal / file inclusion attempt" in names(
        "/vulnerabilities/fi/?page=../../../../etc/passwd")


def test_command_injection():
    assert "Command injection attempt" in names(
        "/vulnerabilities/exec/?ip=127.0.0.1%3Bcat%20%2Fetc%2Fpasswd")


def test_scanner_user_agent():
    assert "Known attack tool detected" in names("/", ua="sqlmap/1.8.4#stable (https://sqlmap.org)")


def test_sensitive_file_probe():
    assert "Sensitive file probe" in names("/.env", status=404)


def test_bruteforce_alerts_once_at_threshold():
    d = Detector(brute_threshold=10)
    hits = []
    for i in range(15):
        hits += [x.rule_name for x in d.check(
            entry(f"/vulnerabilities/brute/?username=admin&password=p{i}&Login=Login"))]
    assert hits.count("Brute-force login attempt") == 1


def test_directory_scan():
    d = Detector(notfound_threshold=20)
    hits = []
    for i in range(25):
        hits += [x.rule_name for x in d.check(entry(f"/hidden-{i}.php", status=404))]
    assert hits.count("Directory scanning") == 1


def test_cooldown_suppresses_duplicates():
    d = Detector()
    e = entry("/?id=1%27%20OR%201=1")
    assert d.check(e) and not d.check(e)
