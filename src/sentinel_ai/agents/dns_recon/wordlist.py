"""Built-in subdomain wordlist for brute-force enumeration."""

from __future__ import annotations

from pathlib import Path

DEFAULT_SUBDOMAINS: list[str] = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "pop3", "ns1", "ns2",
    "ns3", "ns4", "dns", "dns1", "dns2", "mx", "mx1", "mx2", "imap",
    "blog", "admin", "portal", "vpn", "remote", "api", "dev", "staging",
    "test", "beta", "demo", "app", "gateway", "proxy", "cdn", "static",
    "assets", "media", "images", "img", "docs", "wiki", "help", "support",
    "kb", "status", "monitor", "grafana", "prometheus", "kibana", "elastic",
    "jenkins", "ci", "cd", "git", "gitlab", "github", "bitbucket", "svn",
    "repo", "registry", "docker", "k8s", "kube", "kubernetes", "rancher",
    "vault", "consul", "nomad", "terraform", "ansible", "puppet", "chef",
    "salt", "nagios", "zabbix", "icinga", "cacti", "sentry", "log", "logs",
    "syslog", "splunk", "graylog", "elk", "auth", "sso", "login", "oauth",
    "cas", "ldap", "ad", "directory", "radius", "db", "database", "mysql",
    "postgres", "postgresql", "mongo", "mongodb", "redis", "memcached",
    "rabbitmq", "kafka", "mq", "queue", "nfs", "backup", "bak", "old",
    "legacy", "archive", "internal", "intranet", "extranet", "corp",
    "corporate", "office", "erp", "sap", "crm", "salesforce", "jira",
    "confluence", "slack", "teams", "zoom", "meet", "calendar", "exchange",
    "owa", "autodiscover", "lyncdiscover", "sip", "voip", "pbx", "asterisk",
    "shop", "store", "ecommerce", "checkout", "payment", "pay", "billing",
    "cpanel", "whm", "plesk", "panel", "webmin", "phpmyadmin", "pma",
    "cloud", "aws", "azure", "gcp", "s3", "cdn1", "cdn2", "edge",
    "staging1", "staging2", "dev1", "dev2", "test1", "test2", "uat", "qa",
    "sandbox", "preview", "canary", "green", "blue", "prod", "production",
    "www2", "www3", "secure", "ssl", "m", "mobile", "wap", "forum",
    "forums", "community", "social", "chat", "im", "video", "stream",
    "tv", "radio", "news", "press", "ir", "investor", "careers", "jobs",
    "hr", "talent", "training", "learn", "academy", "education",
]


def load_wordlist(path: str | None = None) -> list[str]:
    """Load subdomain wordlist from file or return built-in list."""
    if path is None:
        return DEFAULT_SUBDOMAINS.copy()

    wordlist_path = Path(path)
    if not wordlist_path.is_file():
        raise FileNotFoundError(f"Wordlist file not found: {path}")

    words: list[str] = []
    with open(wordlist_path, "r") as f:
        for line in f:
            word = line.strip()
            if word and not word.startswith("#"):
                words.append(word)
    return words
