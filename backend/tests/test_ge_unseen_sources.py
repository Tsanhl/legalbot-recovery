"""Synthetic, in-memory tests: no bank, network, filesystem writes, or runner import.

Run: python -B -m unittest backend.tests.test_ge_unseen_sources -v
PDF integration tests skip only when pypdf is unavailable; its absence is also
tested explicitly. Fixtures contain technical sample prose, not legal answers.
"""

from __future__ import annotations

import importlib
import importlib.util
import io
import sys
import unittest
import zlib
from unittest.mock import patch

from scripts import ge_unseen_sources as sources


class SourceURLTests(unittest.TestCase):
    def test_uk_and_devolved_official_sources(self):
        urls = (
            "https://gov.uk/", "https://www.gov.uk/guidance/example",
            "https://legislation.gov.uk/ukpga/2020/1/data.xml",
            "https://www.legislation.gov.uk/asp/2020/1/data.xml",
            "https://caselaw.nationalarchives.gov.uk/uksc/2020/1",
            "https://www.scotcourts.gov.uk/media/example.pdf",
            "https://judiciary.scot/", "https://www.judiciary.scot/",
            "https://judiciaryni.uk/judicial-decisions",
            "https://www.judiciaryni.uk/files/example.pdf",
            "https://judiciary.uk/judgments", "https://www.judiciary.uk/judgments",
            "https://supremecourt.uk/", "https://www.supremecourt.uk/example.pdf",
            "https://www.justice-ni.gov.uk/", "HTTPS://WWW.GOV.UK/path?x=1#part",
        )
        for url in urls:
            with self.subTest(url=url):
                self.assertTrue(sources.is_allowed_source_url(url))

    def test_existing_regulator_hosts_and_www_aliases(self):
        for host in ("fca.org.uk", "financial-ombudsman.org.uk", "ico.org.uk", "acas.org.uk"):
            for prefix in ("", "www."):
                with self.subTest(host=prefix + host):
                    self.assertTrue(sources.is_allowed_source_url("https://" + prefix + host + "/"))
            self.assertFalse(sources.is_allowed_source_url("https://unverified." + host))

    def test_devolved_government_hosts_and_spoofs(self):
        for host in ("gov.scot", "gov.wales"):
            self.assertTrue(sources.is_allowed_source_url("https://" + host))
            self.assertTrue(sources.is_allowed_source_url("https://www." + host))
            self.assertFalse(sources.is_allowed_source_url("https://" + host + ".invalid"))
            self.assertFalse(sources.is_allowed_source_url("https://unverified." + host))

    def test_us_federal_state_courts_and_legislatures(self):
        urls = (
            "https://www.supremecourt.gov/opinions/example.pdf",
            "https://www.uscourts.gov/", "https://www.ca9.uscourts.gov/opinions/",
            "https://uscode.house.gov/", "https://www.congress.gov/",
            "https://www.govinfo.gov/content/pkg/example.pdf", "https://www.ecfr.gov/",
            "https://www.nycourts.gov/", "https://courts.ca.gov/",
            "https://www.courts.wa.gov/", "https://www.revisor.mn.gov/statutes/",
            "https://statutes.capitol.texas.gov/", "https://legislature.mi.gov/",
            "https://leg.state.fl.us/", "https://www.leg.state.fl.us/Statutes/",
            "https://www.legis.state.pa.us/", "https://www.palegis.us/",
            "https://www.pacourts.us/opinions/", "https://pacourts.us/",
            "https://www.courts.state.va.us/", "https://courts.state.md.us/",
            "https://www.legislature.state.al.us/", "https://alison.legislature.state.al.us/",
            "https://www.sccourts.org/", "https://sccourts.org/",
        )
        for url in urls:
            with self.subTest(url=url):
                self.assertTrue(sources.is_allowed_source_url(url))

    def test_eu_cross_border_hosts_are_exact(self):
        for host in ("eur-lex.europa.eu", "curia.europa.eu"):
            self.assertTrue(sources.is_allowed_source_url("https://" + host))
            self.assertFalse(sources.is_allowed_source_url("https://other." + host))
        for host in ("europa.eu", "ec.europa.eu", "e-justice.europa.eu"):
            self.assertFalse(sources.is_allowed_source_url("https://" + host))

    def test_nevada_new_hampshire_new_jersey_exact_exceptions(self):
        for host in ("leg.state.nv.us", "gencourt.state.nh.us", "njleg.state.nj.us"):
            with self.subTest(host=host):
                apex, www = "https://" + host, "https://www." + host
                self.assertTrue(sources.is_allowed_source_url(apex))
                self.assertTrue(sources.is_allowed_source_url(www))
                self.assertTrue(sources.redirect_allowed(apex, www))
                self.assertTrue(sources.redirect_allowed(www, apex))
                self.assertFalse(sources.is_allowed_source_url("https://unverified." + host))
                self.assertFalse(sources.is_allowed_source_url(apex + ".evil.example"))
        self.assertTrue(sources.is_allowed_source_url("https://gc.nh.gov/"))
        self.assertTrue(sources.is_allowed_source_url("https://code.dccouncil.gov/"))
        self.assertTrue(sources.redirect_allowed("https://gencourt.state.nh.us/", "https://gc.nh.gov/"))

    def test_verified_publication_and_tribunal_hosts_are_exact(self):
        for host in ("pub.njleg.state.nj.us", "www.catribunal.org.uk"):
            with self.subTest(host=host):
                self.assertTrue(sources.is_allowed_source_url(f"https://{host}/sample.pdf"))
                self.assertTrue(sources.is_allowed_source_url(f"https://{host.upper()}/"))
            for authority in (f"unverified.{host}", f"www.{host}", f"{host}.evil.example",
                              f"evil{host}", f"{host}.", f"{host}:443", f"{host}:80",
                              f"user@{host}", f"{host}@evil.example", host.replace(".", "%2e")):
                with self.subTest(authority=authority):
                    self.assertFalse(sources.is_allowed_source_url(f"https://{authority}/"))
            self.assertFalse(sources.is_allowed_source_url(f"http://{host}/"))
        for host in ("catribunal.org.uk", "unverified.catribunal.org.uk",
                     "other.njleg.state.nj.us", "www.pub.njleg.state.nj.us"):
            self.assertFalse(sources.is_allowed_source_url(f"https://{host}/"))

    def test_new_hampshire_redirect_exception_is_directed_and_exact(self):
        canonical = "https://gc.nh.gov/"
        for host in ("gencourt.state.nh.us", "www.gencourt.state.nh.us"):
            original = f"https://{host}/rsa/html/example.htm"
            self.assertTrue(sources.redirect_allowed(original, canonical + "rsa/html/example.htm"))
            self.assertTrue(sources.redirect_allowed(original.upper(), canonical))
            for target in ("http://gc.nh.gov/", "https://www.gc.nh.gov/",
                           "https://unverified.gc.nh.gov/", "https://another.nh.gov/",
                           "https://gc.nh.gov.evil.example/", "https://gc.nh.gov:443/",
                           "https://user@gc.nh.gov/", "https://gc.nh.gov./",
                           "https://gc%2enh.gov/", "//gc.nh.gov/", "https://gc.nh.gov/%0a"):
                with self.subTest(original=original, target=target):
                    self.assertFalse(sources.redirect_allowed(original, target))
            self.assertFalse(sources.redirect_allowed(canonical, original))
        for original in ("https://unverified.gencourt.state.nh.us/", "https://another.nh.gov/",
                         "https://www.www.gencourt.state.nh.us/", "https://gencourt.state.nh.us:443/",
                         "http://gencourt.state.nh.us/", "https://user@gencourt.state.nh.us/"):
            with self.subTest(original=original):
                self.assertFalse(sources.redirect_allowed(original, canonical))
        # Every subsequent hop still needs its own check; no trust inheritance.
        self.assertTrue(sources.redirect_allowed(canonical, "https://www.gc.nh.gov/"))
        self.assertFalse(sources.redirect_allowed(canonical, "https://another.nh.gov/"))
        self.assertFalse(sources.redirect_allowed(
            "https://www.njleg.state.nj.us/", "https://pub.njleg.state.nj.us/"))
        self.assertFalse(sources.redirect_allowed(
            "https://www.catribunal.org.uk/", "https://www.gov.uk/"))

    def test_adversarial_authorities_and_unapproved_domains(self):
        urls = (
            "https://evilgov.uk", "https://gov.uk.evil.example", "https://gov.uk.org",
            "https://evilgov", "https://supremecourt.gov.evil.example",
            "https://judiciary.scot.evil.example", "https://eviljudiciary.scot",
            "https://evil.judiciaryni.uk", "https://unverified.leg.state.fl.us",
            "https://unverified.pacourts.us", "https://unverified.sccourts.org",
            "https://private.us", "https://courts.state.zz.us", "https://state.fl.us",
            "https://legislature.state.fl.us", "https://private.org", "https://lawblog.com",
            "https://bailii.org", "https://law.cornell.edu",
            "https://gov", "https://gov.uk.", "https://www..gov.uk",
            "https://-court.gov", "https://court-.gov", "https://court_name.gov",
            "https://" + "a" * 64 + ".gov", "https://" + "a." * 127 + "gov",
            "https://gоv.uk", "https://gov。uk", "https://gov．uk", "https://ＧＯＶ.uk",
            "https://xn--gov-9za.uk", "https://xn--example.gov",
            "https://%67ov.uk", "https://gov%2euk", "https://gov.uk%00.evil.example",
            "https://gov.uk@evil.example", "https://evil.example@gov.uk",
            "https://user:password@gov.uk", "https://@gov.uk", "https://user%40gov.uk@usa.gov",
            "https://gov.uk:443", "https://gov.uk:80", "https://gov.uk:8443",
            "https://gov.uk:", "https://gov.uk:notaport", "https://gov.uk:65536",
            "https://gov.uk:0", "https://gov.uk:-1", "https://gov.uk:0443",
            "https://[gov.uk]", "https://[broken", "https://gov.uk]",
            "https://127.0.0.1", "https://127.1", "https://2130706433",
            "https://0177.0.0.1", "https://0x7f000001", "https://192.168.1.1",
            "https://169.254.169.254", "https://8.8.8.8", "https://[::1]",
            "https://[::ffff:127.0.0.1]", "https://[fe80::1%25en0]",
            "https://localhost", "https://foo.localhost", "https://localhost.gov",
        )
        for url in urls:
            with self.subTest(url=url):
                self.assertFalse(sources.is_allowed_source_url(url))

    def test_strict_url_syntax(self):
        urls = (
            None, 42, b"https://gov.uk", "", "//gov.uk/", "gov.uk/",
            "http://gov.uk", "ftp://gov.uk", "file:///gov.uk", "https:gov.uk",
            "https:///gov.uk", " https://gov.uk", "https://gov.uk ",
            "\x00https://gov.uk", "https://gov.\nuk", "https://gov.uk\t/path",
            "https://gov.uk/\r\nHeader:x", "https://gov.uk/\x7f", "https://gov.uk/\u00a0",
            "https://evil.example\\@gov.uk", "https://gov.uk\\evil.example",
            "https://gov.uk/%0d%0aHeader:x", "https://gov.uk/%00", "https://gov.uk/%7f",
            "https://gov.uk/%zz", "https://gov.uk/%", "https://gov.uk/" + "x" * 8_192,
        )
        for url in urls:
            with self.subTest(url=url):
                self.assertFalse(sources.is_allowed_source_url(url))
        self.assertTrue(sources.is_allowed_source_url("https://gov.uk/a%20b?x=%2F#section"))

    def test_redirects_require_two_valid_equivalent_hosts(self):
        allowed = (
            ("https://gov.uk/a", "https://gov.uk/b?x=1"),
            ("https://gov.uk/a", "https://www.gov.uk/b"),
            ("https://WWW.GOV.UK/a", "https://gov.uk/b"),
            ("https://www.judiciary.scot/", "https://judiciary.scot/decisions"),
            ("https://leg.state.fl.us/", "https://www.leg.state.fl.us/Welcome/"),
            ("https://www.supremecourt.gov/a", "https://supremecourt.gov/b"),
            ("https://eur-lex.europa.eu/a", "https://eur-lex.europa.eu/b"),
        )
        held = (
            ("https://gov.uk", "https://legislation.gov.uk"),
            ("https://agency.gov/a", "https://another.agency.gov/a"),
            ("https://agency.gov", "https://agency.gov.uk"),
            ("https://www.legis.state.pa.us/", "https://www.palegis.us/"),
            ("https://www.legislature.state.al.us/", "https://alison.legislature.state.al.us/"),
            ("https://eur-lex.europa.eu", "https://curia.europa.eu"),
            ("https://gov.uk", "https://evil.example"),
            ("https://evil.example", "https://gov.uk"),
            ("https://private.org", "https://www.private.org"),
            ("https://gov.uk", "http://gov.uk"),
            ("http://gov.uk", "https://gov.uk"),
            ("https://gov.uk", "https://user@gov.uk"),
            ("https://gov.uk:443", "https://gov.uk"),
            ("https://gov.uk", "https://gov.uk:443"),
            ("https://gov.uk", "https://gov.uk."),
            ("https://gov.uk", "//gov.uk/new"),
            ("https://gov.uk", "/new"),
            (None, "https://gov.uk"),
        )
        for original, final in allowed:
            with self.subTest(original=original, final=final):
                self.assertTrue(sources.redirect_allowed(original, final))
        for original, final in held:
            with self.subTest(original=original, final=final):
                self.assertFalse(sources.redirect_allowed(original, final))


class MarkupTextTests(unittest.TestCase):
    def test_namespaced_xml_entities_and_sections(self):
        raw = (b'<?xml version="1.0" encoding="UTF-8"?>'
               b'<Legislation xmlns="urn:public-technical-test">'
               b'<Number>1</Number><Text>Alpha &amp; beta &#163;5.</Text>'
               b'<Text>Second paragraph.</Text></Legislation>')
        self.assertEqual(sources.source_text(raw), "1 Alpha & beta £5. Second paragraph.")

    def test_html_ignores_active_content_preserves_inline_words_and_boundaries(self):
        raw = (b'<!DOCTYPE html><html><head><title>Example</title>'
               b'<style>.hidden {content: "not evidence"}</style></head><body>'
               b'<script>not_evidence()</script><p>Technical con<b>tract</b> sample.</p>'
               b'<p>Next&nbsp;paragraph<br/>Line two &amp; more.</p>'
               b'<table><tr><td>Alpha</td><td>Beta</td></tr></table>'
               b'<template>Hidden<template>Nested</template></template>'
               b'<noscript>Fallback</noscript><iframe>Frame</iframe>'
               b'<!-- comment --> <p>Visible</p></body></html>')
        self.assertEqual(sources.source_text(raw),
                         "Example Technical contract sample. Next paragraph Line two & more. Alpha Beta Visible")

    def test_html_fragments_and_xhtml(self):
        self.assertEqual(sources.source_text(b"<p>One<p>Two<br>Three"), "One Two Three")
        self.assertEqual(sources.source_text(b'<p>A<svg/><em>B</em></p>'), "AB")
        self.assertEqual(sources.source_text(
            b'<?xml version="1.0"?><html xmlns="http://www.w3.org/1999/xhtml">'
            b'<body><script>hidden</script><p>Visible</p></body></html>'), "Visible")

    def test_explicit_supported_encodings(self):
        for encoding in ("utf-8-sig", "utf-16", "utf-32"):
            with self.subTest(encoding=encoding):
                self.assertEqual(sources.source_text("<Text>Café £5.</Text>".encode(encoding)), "Café £5.")
        self.assertEqual(sources.source_text(
            b'<?xml version="1.0" encoding="ISO-8859-1"?><Text>Caf\xe9</Text>'), "Café")
        self.assertEqual(sources.source_text(
            b'<html><head><meta charset="windows-1252"></head><body><p>\x93sample\x94</p></body></html>'),
            "“sample”")

    def test_rejects_entities_and_dtds_without_html_fallback(self):
        payloads = (
            '<!DOCTYPE Text [<!ENTITY x "expanded">]><Text>&x;</Text>',
            '<!DOCTYPE html [<!ENTITY x SYSTEM "file:///not-read">]><html>&x;</html>',
            '<!DOCTYPE Text SYSTEM "https://example.invalid/not-fetched"><Text>Sample</Text>',
        )
        for payload in payloads:
            for encoding in ("utf-8", "utf-16", "utf-32"):
                with self.subTest(payload=payload, encoding=encoding), self.assertRaisesRegex(
                    sources.SourceTextError, "XML_DTD_FORBIDDEN"
                ):
                    sources.source_text(payload.encode(encoding))

    def test_binary_non_markup_malformed_and_empty_inputs_fail_closed(self):
        payloads = (
            b"", b"\x89PNG\r\n\x1a\n", b"PK\x03\x04archive", b"\x1f\x8bcompressed",
            b"%PDF-invalid-without-header", b"plain text", b'{"text": "not markup"}',
            b"<Text>\xff</Text>", b"<Text>\x00binary</Text>", b"<p>\x7f</p>",
            b"<p>&#0;</p>", b"<Text>unclosed", b"<?xml version='1.0'?><p>unclosed",
            b"<Text>&undeclared;</Text>", b"<Text> </Text>", b"<html><script>hidden</script></html>",
            b'<?xml version="1.0" encoding="utf-7"?><Text>sample</Text>',
        )
        for raw in payloads:
            with self.subTest(raw=raw), self.assertRaises(sources.SourceTextError):
                sources.source_text(raw)
        for raw in (None, "<p>text</p>", bytearray(b"<p>text</p>")):
            with self.assertRaisesRegex(sources.SourceTextError, "SOURCE_BYTES_REQUIRED"):
                sources.source_text(raw)

    def test_input_and_output_limits_raise_without_truncating(self):
        raw = b"<p>Technical sample</p>"
        with patch.object(sources, "MAX_SOURCE_BYTES", len(raw) - 1), self.assertRaisesRegex(
            sources.SourceTextError, "SOURCE_BYTE_LIMIT"
        ):
            sources.source_text(raw)
        for payload in (raw, b"<Text>Technical sample</Text>"):
            with patch.object(sources, "MAX_TEXT_CHARS", 5), self.assertRaisesRegex(
                sources.SourceTextError, "SOURCE_TEXT_TOO_LARGE"
            ):
                sources.source_text(payload)

    def test_lazy_import_and_missing_pdf_dependency(self):
        with patch.dict(sys.modules, {"pypdf": None}):
            importlib.reload(sources)
            self.assertEqual(sources.source_text(b"<p>HTML sample</p>"), "HTML sample")
            self.assertEqual(sources.source_text(b"<Text>XML sample</Text>"), "XML sample")
            with self.assertRaisesRegex(sources.SourceTextError, "PDF_EXTRACTION_UNAVAILABLE"):
                sources.source_text(_pdf_fixture(("PDF sample",)))


# Same prolog/root structure as the live OLRC view.xhtml page checked 2026-09-05;
# all body text is synthetic and has no legal/currentness significance.
_XHTML_DOCTYPE = ('<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" '
                  '"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">')
_XHTML_START = '<html xmlns="http://www.w3.org/1999/xhtml">'


class XHTMLTextTests(unittest.TestCase):
    def test_olrc_structure_uses_inert_tolerant_html_without_xml_or_io(self):
        raw = ("<?xml version='1.0' encoding='UTF-8' ?>\n" + _XHTML_DOCTYPE + "\n" + _XHTML_START
               + '<head><title>Transport sample</title><style>hidden</style></head><body>'
               '<script src="https://example.invalid/not-fetched">hidden()</script>'
               '<p>Inline trans<b>port</b> &amp; text&nbsp;&sect; 1 &euro;5.<br>Next line.'
               '<p>Loose & text.</p><template>hidden</template>'
               '<iframe src="file:///not-read">hidden</iframe>'
               '<img src="https://example.invalid/not-fetched">'
               '</body></html>').encode()
        # Patching XML itself proves that a permissive XML resolver is not the
        # implementation; these I/O sentinels also forbid any DTD/resource load.
        with (patch.object(sources.ElementTree, "fromstring") as xml_parse,
              patch("urllib.request.urlopen") as urlopen,
              patch("socket.create_connection") as connect,
              patch("socket.socket") as socket,
              patch("builtins.open") as file_open):
            self.assertEqual(sources.source_text(raw),
                             "Transport sample Inline transport & text § 1 €5. Next line. Loose & text.")
            for sentinel in (xml_parse, urlopen, connect, socket, file_open):
                sentinel.assert_not_called()

    def test_known_doctype_quotes_whitespace_comments_and_encodings(self):
        doctypes = (_XHTML_DOCTYPE, _XHTML_DOCTYPE.replace('"', "'"),
                    _XHTML_DOCTYPE.replace(' PUBLIC ', '\nPUBLIC\t').replace(' "http:', '\n"http:'))
        for doctype in doctypes:
            for declaration in ("", "<?xml version='1.0' ?>\n"):
                text = (declaration + '<!-- <Text>not the root</Text> -->\n<!-- Second comment -->\n' + doctype
                        + "\n<!-- <p>not the root</p> -->" + _XHTML_START
                        + '<body><p>Café&nbsp;£5.</p></body></html>')
                for encoding in ("utf-8", "utf-8-sig", "utf-16", "utf-32"):
                    with self.subTest(doctype=doctype, declaration=declaration, encoding=encoding):
                        self.assertEqual(sources.source_text(text.encode(encoding)), "Café £5.")

    def test_doctype_requires_actual_html_root_and_exact_namespace(self):
        bodies = (
            '<Text>Sample</Text>', '<html><p>Sample</p></html>',
            '<html xmlns="urn:other"><p>Sample</p></html>',
            '<html xmlns="http://www.w3.org/1999/xhtml.evil.example"><p>Sample</p></html>',
            '<html data-xmlns="http://www.w3.org/1999/xhtml"><p>Sample</p></html>',
            '<html xmlns="urn:other" xmlns="http://www.w3.org/1999/xhtml">Sample</html>',
            '<Text>' + _XHTML_START + '<p>Sample</p></html></Text>',
            '<!-- ' + _XHTML_START + ' --><p>Sample</p>',
            'Not a document ' + _XHTML_START + '<p>Sample</p></html>',
        )
        for body in bodies:
            with self.subTest(body=body), self.assertRaisesRegex(sources.SourceTextError, "XML_DTD_FORBIDDEN"):
                sources.source_text((_XHTML_DOCTYPE + body).encode())

    def test_unknown_external_dtds_and_identifier_spoofs_are_rejected(self):
        doctypes = (
            '<!DOCTYPE html SYSTEM "file:///not-read">',
            '<!DOCTYPE html SYSTEM "https://example.invalid/not-fetched">',
            _XHTML_DOCTYPE.replace('www.w3.org/', 'www.w3.org.evil.example/'),
            _XHTML_DOCTYPE.replace('http://www.w3.org/', 'file:///'),
            _XHTML_DOCTYPE.replace('Transitional//EN', 'Unverified//EN'),
            _XHTML_DOCTYPE.replace('transitional.dtd', 'other.dtd'),
            _XHTML_DOCTYPE.replace('DOCTYPE html', 'DOCTYPE Text'),
            _XHTML_DOCTYPE.replace('transitional.dtd', 'transitional.dtd?extra=1'),
            _XHTML_DOCTYPE[:-1],
        )
        for doctype in doctypes:
            for declaration in ("", "<?xml version='1.0'?>"):
                with self.subTest(doctype=doctype, declaration=declaration), self.assertRaisesRegex(
                    sources.SourceTextError, "XML_DTD_FORBIDDEN"
                ):
                    sources.source_text((declaration + doctype + _XHTML_START + '<p>Sample</p></html>').encode())

    def test_internal_external_parameter_and_exponential_entities_fail_before_parsing(self):
        exponential = '<!ENTITY e0 "sample">' + ''.join(
            f'<!ENTITY e{level} "' + f'&e{level - 1};' * 10 + '">'
            for level in range(1, 10)
        )
        subsets = (
            '', '<!ENTITY x "expanded">', '<!ENTITY x SYSTEM "file:///not-read">',
            '<!ENTITY x SYSTEM "https://example.invalid/not-fetched">',
            '<!ENTITY % remote SYSTEM "https://example.invalid/not-fetched">%remote;',
            '<!ENTITY % remote SYSTEM "file:///not-read">%remote;', exponential,
        )
        payloads = [_XHTML_DOCTYPE[:-1] + ' [' + subset + ']>' + _XHTML_START
                    + '<p>&x;&e9;</p></html>' for subset in subsets]
        payloads.append(_XHTML_DOCTYPE + _XHTML_START + '<!ENTITY x "expanded"><p>&x;</p></html>')
        with (patch.object(sources.ElementTree, "fromstring") as xml_parse,
              patch.object(sources._HTMLText, "feed") as html_parse):
            for payload in payloads:
                for encoding in ("utf-8", "utf-16", "utf-32"):
                    with self.subTest(payload=payload, encoding=encoding), self.assertRaisesRegex(
                        sources.SourceTextError, "XML_DTD_FORBIDDEN"
                    ):
                        sources.source_text(payload.encode(encoding))
            xml_parse.assert_not_called()
            html_parse.assert_not_called()

    def test_duplicate_displaced_and_commented_doctypes_fail_closed(self):
        body = _XHTML_START + '<p>Sample</p></html>'
        payloads = (
            _XHTML_DOCTYPE + _XHTML_DOCTYPE + body,
            '<!DOCTYPE html>' + _XHTML_DOCTYPE + body,
            '<!-- ' + _XHTML_DOCTYPE + ' -->' + body,
            '<Text>' + _XHTML_DOCTYPE + body + '</Text>',
            _XHTML_DOCTYPE + body + '<!DOCTYPE html SYSTEM "file:///not-read">',
        )
        for payload in payloads:
            with self.subTest(payload=payload), self.assertRaisesRegex(sources.SourceTextError, "XML_DTD_FORBIDDEN"):
                sources.source_text(payload.encode())

    def test_xhtml_limits_empty_text_and_strict_xml_route_remain_enforced(self):
        raw = (_XHTML_DOCTYPE + _XHTML_START + '<p>Transport sample</p></html>').encode()
        for constant, value, error in (("MAX_SOURCE_BYTES", len(raw) - 1, "SOURCE_BYTE_LIMIT"),
                                       ("MAX_TEXT_CHARS", 5, "SOURCE_TEXT_TOO_LARGE")):
            with patch.object(sources, constant, value), self.assertRaisesRegex(sources.SourceTextError, error):
                sources.source_text(raw)
        with self.assertRaisesRegex(sources.SourceTextError, "SOURCE_TEXT_EMPTY"):
            sources.source_text((_XHTML_DOCTYPE + _XHTML_START + '<script>hidden</script></html>').encode())
        with self.assertRaisesRegex(sources.SourceTextError, "XML_PARSE_FAILED"):
            sources.source_text(("<?xml version='1.0'?>" + _XHTML_START + '<p>&nbsp;</p></html>').encode())


def _pdf_fixture(pages: tuple[str, ...], *, compressed: bool = True) -> bytes:
    """Small valid PDF with a real text layer and xref, entirely in memory."""
    kids = " ".join(f"{4 + index * 2} 0 R" for index in range(len(pages)))
    objects = [b"<< /Type /Catalog /Pages 2 0 R >>",
               f"<< /Type /Pages /Kids [{kids}] /Count {len(pages)} >>".encode(),
               b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    for index, text in enumerate(pages):
        content_id = 5 + index * 2
        objects.append(("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                        "/Resources << /Font << /F1 3 0 R >> >> "
                        f"/Contents {content_id} 0 R >>").encode())
        escaped = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        stream = f"BT /F1 12 Tf 72 720 Td ({escaped}) Tj ET".encode("ascii")
        if compressed:
            stream = zlib.compress(stream)
        filter_part = " /Filter /FlateDecode" if compressed else ""
        objects.append(f"<< /Length {len(stream)}{filter_part} >>\nstream\n".encode()
                       + stream + b"\nendstream")
    data = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for number, obj in enumerate(objects, start=1):
        offsets.append(len(data))
        data.extend(f"{number} 0 obj\n".encode() + obj + b"\nendobj\n")
    xref = len(data)
    data.extend(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode())
    for offset in offsets:
        data.extend(f"{offset:010d} 00000 n \n".encode())
    data.extend(f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
    return bytes(data)


@unittest.skipUnless(importlib.util.find_spec("pypdf"), "pypdf unavailable")
class PDFTextTests(unittest.TestCase):
    def test_actual_compressed_pdf_extraction_in_page_order(self):
        raw = _pdf_fixture(("First technical sample.", "Second technical sample."))
        self.assertNotIn(b"First technical sample.", raw)
        self.assertEqual(sources.source_text(raw), "First technical sample. Second technical sample.")
        self.assertEqual(sources.source_text(_pdf_fixture(("Uncompressed sample",), compressed=False)),
                         "Uncompressed sample")

    def test_corrupt_pdf_has_bounded_error_and_never_falls_back_to_html(self):
        with self.assertRaises(sources.SourceTextError) as raised:
            sources.source_text(b"%PDF-1.4\n<p>must not become source text</p>\n%%EOF\n")
        self.assertEqual(str(raised.exception), "PDF_EXTRACTION_FAILED")

    def test_blank_and_zero_page_pdf_hold(self):
        with self.assertRaisesRegex(sources.SourceTextError, "SOURCE_TEXT_EMPTY"):
            sources.source_text(_pdf_fixture(("",)))
        with self.assertRaisesRegex(sources.SourceTextError, "PDF_PAGE_LIMIT"):
            sources.source_text(_pdf_fixture(()))

    def test_encrypted_pdf_holds(self):
        from pypdf import PdfReader, PdfWriter

        writer = PdfWriter()
        writer.add_page(PdfReader(io.BytesIO(_pdf_fixture(("Technical sample",)))).pages[0])
        writer.encrypt("public-synthetic-test-password")
        buffer = io.BytesIO()
        writer.write(buffer)
        with self.assertRaisesRegex(sources.SourceTextError, "PDF_ENCRYPTED"):
            sources.source_text(buffer.getvalue())

    def test_pdf_page_content_and_text_limits(self):
        raw = _pdf_fixture(("First technical sample.", "Second technical sample."))
        for constant, value, error in (
            ("MAX_PDF_PAGES", 1, "PDF_PAGE_LIMIT"),
            ("MAX_PDF_CONTENT_BYTES", 10, "PDF_CONTENT_TOO_LARGE"),
            ("MAX_TEXT_CHARS", 10, "SOURCE_TEXT_TOO_LARGE"),
        ):
            with self.subTest(constant=constant), patch.object(sources, constant, value), self.assertRaisesRegex(
                sources.SourceTextError, error
            ):
                sources.source_text(raw)


if __name__ == "__main__":
    unittest.main()
