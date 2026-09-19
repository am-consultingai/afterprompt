"""The website in site/ stays consistent with the code and README (site plan W-1..W-7)."""
import html.parser
import os
import re
import unittest

from afterprompt import __version__, catalogue
from afterprompt.patterns import PATTERNS
from tests.helpers import REPO

SITE = os.path.join(REPO, "site")


def read(*parts):
    with open(os.path.join(REPO, *parts), encoding="utf-8") as fh:
        return fh.read()


class Collector(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids, self.hrefs, self.scripts, self.styles, self.meta, self.tags = set(), [], [], [], {}, []
        self.data_version, self.data_patterns = [], []
        self._capture = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        self.tags.append(tag)
        if "id" in a:
            self.ids.add(a["id"])
        if tag == "a" and "href" in a:
            self.hrefs.append(a["href"])
        if tag == "script" and a.get("src"):
            self.scripts.append(a["src"])
        if tag == "link" and a.get("rel") == "stylesheet":
            self.styles.append(a["href"])
        if tag == "meta":
            key = a.get("name") or a.get("property")
            if key:
                self.meta[key] = a.get("content", "")
        if "data-version" in a:
            self._capture = self.data_version
        elif "data-patterns" in a:
            self._capture = self.data_patterns

    def handle_data(self, data):
        if self._capture is not None:
            self._capture.append(data.strip())
            self._capture = None


class SiteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = read("site", "index.html")
        cls.page = Collector()
        cls.page.feed(cls.html)

    def test_version(self):  # W-1
        self.assertTrue(self.page.data_version)
        self.assertEqual(set(self.page.data_version), {__version__})

    def test_pattern_count(self):  # W-2
        self.assertTrue(self.page.data_patterns)
        self.assertEqual(set(self.page.data_patterns), {str(len(PATTERNS))})

    def test_quick_start_matches_readme(self):  # W-3
        readme = read("README.md")
        block = re.search(r"## Quick start\s+```bash\n(.*?)```", readme, re.S).group(1)
        start = re.search(r'<section[^>]*id="start".*?</section>', self.html, re.S).group(0)
        for line in (l.strip() for l in block.splitlines() if l.strip()):
            self.assertIn(line, start)

    def test_internal_links_resolve(self):  # W-4
        for href in self.page.hrefs:
            if href.startswith("#"):
                self.assertIn(href[1:], self.page.ids, href)

    def test_allowed_resources(self):  # W-5
        self.assertEqual(self.page.scripts, ["site.js"])
        for href in self.page.styles:
            self.assertTrue(href == "site.css" or href.startswith("https://fonts.googleapis.com/")
                            or href.startswith("https://cdn.jsdelivr.net/gh/am-consultingai/am-assets@v2/"), href)
        self.assertNotIn("am-assets@main", self.html)
        for f in ("site.css", "site.js", "og.png", "img/report.webp", "img/hero-hacker.webp", "img/hero-hacker-sm.webp",
                  "img/desk.webp", "img/afterprompt-mark.svg"):
            self.assertTrue(os.path.exists(os.path.join(SITE, f)), f)

    def test_am_branding_footer_only(self):
        # Product page rule: the product's mark leads; AM appears only as "Powered by" in the footer.
        footer = re.search(r"<footer.*?</footer>", self.html, re.S).group(0)
        body = self.html.replace(footer, "")
        self.assertIn("Powered by", footer)
        self.assertIn("am-assets@v2/logo/am-logo-white-600.png", footer)
        self.assertNotIn("am-logo", body)
        self.assertNotIn("am-favicon", body)
        self.assertIn('rel="icon" type="image/svg+xml" href="img/afterprompt-mark.svg"', self.html)

    def test_head(self):  # W-7
        self.assertIn('<html lang="en">', self.html)
        self.assertEqual(self.page.tags.count("h1"), 1)
        self.assertRegex(self.html, r"<title>[^<]+</title>")
        for key in ("description", "og:title", "og:description", "og:image", "og:url"):
            self.assertTrue(self.page.meta.get(key), key)

    def test_example_keys_are_marked_fake(self):  # W-8
        # Every credential-looking example on the page ends in DEMO and is labelled as an illustration.
        for m in re.finditer(r"(?:sk-ant|ghp_|sk_live|xai-|AKIA)[\w\-…]*", self.html):
            self.assertTrue(m.group(0).endswith("DEMO"), m.group(0))
        self.assertIn("Not a real key", self.html)
        self.assertIn("Demo data", self.html)

    def test_local_images_exist(self):  # W-9
        for src in re.findall(r'(?:src|srcset|href)="(img/[^"]+)"', self.html):
            self.assertTrue(os.path.exists(os.path.join(SITE, src)), src)

    def test_supported_tools_are_honest(self):  # W-10
        # Only tools the scanner actually covers may be marked as scanned, and every one it covers is.
        scanned = set(re.findall(r'<div class="tool on"[^>]*>(?:<img[^>]*>|<span class="mono-mark">[^<]*</span>)'
                                 r'([^<]+)<b>Scanned</b>', self.html))
        self.assertEqual(scanned, set(catalogue.scanned_products()))

