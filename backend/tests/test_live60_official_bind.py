from __future__ import annotations

from app.evaluation.live_suite_final_check import locator_key, provision_keys
from app.evaluation.live_suite_official_bind import (
    AYINDE_FCL_PARA7_STEM,
    AYINDE_PACK_PARA7_PARAPHRASE,
    ayinde_quote_is_paraphrase,
    bind_targets,
    contains_omitted_dots,
    cpr_gold_url,
    extract_fcl_paragraphs,
    extract_legislation_subsections,
    is_omitted_official_text,
    is_spliced_join,
    limitation_4a_uses_official_opening,
    locator_covers,
    lookup_subsection,
    official_page_is_omitted,
    official_page_urls,
    official_s47_is_digital_content,
    pack_quote_is_services_exclusion,
    rule_keys,
)

ECCTA_S196_XML = """
<Legislation xmlns="http://www.legislation.gov.uk/namespaces/legislation">
  <P1 id="section-196"><Pnumber>196</Pnumber><P1para><Text>. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .</Text></P1para></P1>
  <Commentaries><Commentary Type="F"><Para><Text>S. 196 omitted (29.6.2026) by virtue of Crime and Policing Act 2026</Text></Para></Commentary></Commentaries>
</Legislation>
"""
CPA_S250_XML = """
<Legislation xmlns="http://www.legislation.gov.uk/namespaces/legislation">
  <P1 id="section-250"><Pnumber>250</Pnumber><P1para>
    <P2 id="section-250-1"><Pnumber>1</Pnumber><P2para>
      <Text>Where a senior manager of a body corporate or partnership (“the organisation”) acting within the actual or apparent scope of their authority commits an offence under the law of England and Wales, Scotland or Northern Ireland, the organisation also commits the offence (subject to subsection (2)).</Text>
    </P2para></P2>
  </P1para></P1>
</Legislation>
"""
CRA_S47_XML = """
<Legislation xmlns="http://www.legislation.gov.uk/namespaces/legislation">
  <P1 id="section-47"><Pnumber>47</Pnumber><P1para>
    <P2 id="section-47-1"><Pnumber>1</Pnumber><P2para>
      <Text>A term of a contract to supply digital content is not binding on the consumer to the extent that it would exclude or restrict the trader's liability arising under any of these provisions—</Text>
      <P3 id="section-47-1-a"><Pnumber>a</Pnumber><P3para><Text>section 34 (digital content to be of satisfactory quality),</Text></P3para></P3>
    </P2para></P2>
  </P1para></P1>
</Legislation>
"""
CRA_S57_XML = """
<Legislation xmlns="http://www.legislation.gov.uk/namespaces/legislation">
  <P1 id="section-57"><Pnumber>57</Pnumber><P1para>
    <P2 id="section-57-1"><Pnumber>1</Pnumber><P2para>
      <Text>A term of a contract to supply services is not binding on the consumer to the extent that it would exclude the trader's liability arising under section 49 (service to be performed with reasonable care and skill).</Text>
    </P2para></P2>
    <P2 id="section-57-2"><Pnumber>2</Pnumber><P2para>
      <Text>Subject to section 50(2), a term of a contract to supply services is not binding on the consumer to the extent that it would exclude the trader's liability arising under section 50 (information about trader or service to be binding).</Text>
    </P2para></P2>
    <P2 id="section-57-3"><Pnumber>3</Pnumber><P2para>
      <Text>A term of a contract to supply services is not binding on the consumer to the extent that it would restrict the trader's liability arising under any of sections 49 and 50 and, where they apply, sections 51 and 52 (reasonable price and reasonable time), if it would prevent the consumer in an appropriate case from recovering the price paid or the value of any other consideration.</Text>
    </P2para></P2>
  </P1para></P1>
</Legislation>
"""
LIMITATION_4A_XML = """
<Legislation xmlns="http://www.legislation.gov.uk/namespaces/legislation">
  <P1 id="section-4A"><Pnumber>4A</Pnumber><P1para>
    <Text>The time limit under section 2 of this Act shall not apply to an action for—</Text>
    <P3 id="section-4A-a"><Pnumber>a</Pnumber><P3para><Text>libel or slander, or</Text></P3para></P3>
    <P3 id="section-4A-b"><Pnumber>b</Pnumber><P3para><Text>slander of title, slander of goods or other malicious falsehood,</Text></P3para></P3>
    <Text>but no such action shall be brought after the expiration of one year from the date on which the cause of action accrued.</Text>
  </P1para></P1>
</Legislation>
"""
AYINDE_HTML = """
<section class="judgment-body__section" id="para_6"><span class="judgment-body__number">6.</span>
<p>In the context of legal research, the risks of using artificial intelligence are now well known.</p>
</section>
<section class="judgment-body__section" id="para_7"><span class="judgment-body__number">7.</span>
<p>Those who use artificial intelligence to conduct legal research notwithstanding these risks have a professional duty therefore to check the accuracy of such research by reference to authoritative sources, before using it in the course of their professional work (to advise clients or before a court, for example).</p>
</section>
"""
PACK_S47_SERVICES = (
    "A term of a contract to supply a service is not binding on the consumer to the "
    "extent that it would exclude the trader's liability arising under section 49, 50 or 52."
)
PACK_S4A_REWRITE = (
    "An action for— (a) libel or slander, (b) slander of title, (c) slander of goods "
    "or other malicious falsehood, shall not be brought after the expiration of one year "
    "from the date on which the cause of action accrued."
)
PACK_AYINDE_PARA7 = (
    "Those who use artificial intelligence tools to conduct legal research therefore "
    "have a professional responsibility to check the accuracy of such research by "
    "reference to authoritative sources, before using it in the course of their "
    "professional work (to advise clients or before a court, for example)."
)


def test_eccta_s196_official_page_is_omitted() -> None:
    assert official_page_is_omitted(ECCTA_S196_XML)
    subsections = extract_legislation_subsections(ECCTA_S196_XML)
    assert is_omitted_official_text(subsections["s 196"])
    current = extract_legislation_subsections(CPA_S250_XML)
    assert "organisation also commits the offence" in current["s 250(1)"]
    assert not is_omitted_official_text(current["s 250(1)"])


def test_cra_s47_is_digital_content_not_pack_services_sentence() -> None:
    official = extract_legislation_subsections(CRA_S47_XML)["s 47(1)"]
    services = extract_legislation_subsections(CRA_S57_XML)
    assert official_s47_is_digital_content(official)
    assert pack_quote_is_services_exclusion(PACK_S47_SERVICES)
    assert not pack_quote_is_services_exclusion(official)
    assert "s 57(1)" in services and "s 57(2)" in services and "s 57(3)" in services
    assert services["s 57(1)"] not in services["s 57(2)"]
    synthesised = " ".join(services[key] for key in ("s 57(1)", "s 57(2)", "s 57(3)"))
    assert synthesised != PACK_S47_SERVICES


def test_ayinde_pack_quote_is_paraphrase_of_fcl() -> None:
    paragraphs = extract_fcl_paragraphs(AYINDE_HTML)
    assert "well known" in paragraphs[6]
    assert AYINDE_FCL_PARA7_STEM in paragraphs[7].casefold()
    assert AYINDE_PACK_PARA7_PARAPHRASE in PACK_AYINDE_PARA7.casefold()
    assert ayinde_quote_is_paraphrase(PACK_AYINDE_PARA7, paragraphs[7])
    assert not ayinde_quote_is_paraphrase(paragraphs[7], paragraphs[7])


def test_limitation_s4a_official_opening_and_spliced_parent() -> None:
    official = extract_legislation_subsections(LIMITATION_4A_XML)["s 4A"]
    assert limitation_4a_uses_official_opening(official)
    assert not limitation_4a_uses_official_opening(PACK_S4A_REWRITE)
    spliced = (
        "section 4A The time limit under section 2 of this Act shall not apply to an "
        "action for—but no such action shall be brought after the expiration of one year "
        "from the date on which the cause of action accrued."
    )
    assert is_spliced_join(spliced)
    assert not is_spliced_join(official)


def test_cpr_gold_url_is_legislation_not_justice() -> None:
    url = cpr_gold_url("r 54.5(1)")
    assert url.startswith("https://www.legislation.gov.uk/uksi/1998/3132")
    assert "justice.gov.uk" not in url
    assert url.endswith("/rule/54.5")
    assert rule_keys("r 31.20") == ("r 31.20",)
    xml = """
    <Legislation xmlns="http://www.legislation.gov.uk/namespaces/legislation">
      <P1 id="rule-31.20"><Pnumber>31.20</Pnumber><P1para>
        <Text>Where a party inadvertently allows a privileged document to be inspected, the party who has inspected the document may use it or its contents only with the permission of the court.</Text>
      </P1para></P1>
    </Legislation>
    """
    found = extract_legislation_subsections(xml)
    assert "permission of the court" in found["r 31.20"]


def test_omitted_dots_are_not_gold_text() -> None:
    preferential = (
        "Preferential debts— (a) . . . . . . . . . . . . . . . . . . . . . . . . "
        "(b) rank equally among themselves after the expenses of the winding up."
    )
    assert contains_omitted_dots(preferential)
    assert not contains_omitted_dots("A person (A) discriminates against another (B).")


def test_extracts_regulations_articles_and_cpr_rule_paragraphs() -> None:
    regulation_xml = """
    <Legislation xmlns="http://www.legislation.gov.uk/namespaces/legislation">
      <P1 id="regulation-3"><Pnumber>3</Pnumber><P1para>
        <P2 id="regulation-3-1"><Pnumber>1</Pnumber>
          <P2para><Text>The acquisition, use or disclosure of a trade secret is unlawful.</Text></P2para>
        </P2>
      </P1para></P1>
    </Legislation>
    """
    article_xml = """
    <Legislation xmlns="http://www.legislation.gov.uk/namespaces/legislation">
      <P1 id="article-5"><Pnumber>Article 5</Pnumber><P1para>
        <P2 id="article-5-1"><Pnumber>1</Pnumber><P2para>
          <Text>Personal data shall be:</Text>
          <P3 id="article-5-1-a"><Pnumber>a</Pnumber>
            <P3para><Text>processed lawfully, fairly and in a transparent manner.</Text></P3para>
          </P3>
        </P2para></P2>
      </P1para></P1>
    </Legislation>
    """
    rule_xml = """
    <Legislation xmlns="http://www.legislation.gov.uk/namespaces/legislation">
      <P1 id="rule-54.5"><Pnumber>54.5</Pnumber><P1para>
        <P2 id="rule-54.5-1"><Pnumber>1</Pnumber><P2para>
          <Text>The claim form must be filed—</Text>
          <P3 id="rule-54.5-1-a"><Pnumber>a</Pnumber>
            <P3para><Text>promptly; and</Text></P3para>
          </P3>
        </P2para></P2>
      </P1para></P1>
    </Legislation>
    """
    regulations = extract_legislation_subsections(regulation_xml)
    articles = extract_legislation_subsections(article_xml)
    rules = extract_legislation_subsections(rule_xml)
    assert "unlawful" in regulations["reg 3"]
    assert "unlawful" in regulations["reg 3(1)"]
    assert "processed lawfully" in articles["art 5(1)(a)"]
    assert "Personal data shall be" in articles["art 5(1)"]
    assert articles["art 5(1)"] != articles["art 5(1)(a)"]
    assert "The claim form must be filed" in rules["r 54.5(1)"]
    assert lookup_subsection(rules, "r 54.5(1)").startswith("The claim form must be filed")


def test_bind_targets_split_multi_section_and_mixed_cpr_urls() -> None:
    assert provision_keys("ss 94(1) and 139(1)") == ("s 94(1)", "s 139(1)")
    assert provision_keys("Art 5(1)(a)") == ("art 5(1)(a)",)
    assert "s 29a(1)" in provision_keys("s 29A(1)")
    assert bind_targets("ss 17(1) and 20(1)", "") == ("s 17(1)", "s 20(1)")
    assert bind_targets(
        "ss 94(1) and 139(1)",
        "https://www.legislation.gov.uk/ukpga/1996/18/section/94",
    ) == ("s 94(1)", "s 139(1)")
    assert "s 6a(1)" in bind_targets("s 6A(1)-(2)", "")
    assert "s 6a(2)" in bind_targets("s 6A(1)-(2)", "")
    urls = official_page_urls(
        "https://www.legislation.gov.uk/ukpga/1979/54/sections/17-20",
        "ss 17(1) and 20(1)",
        "Sale of Goods Act 1979",
    )
    assert "https://www.legislation.gov.uk/ukpga/1979/54/section/17" in urls
    assert "https://www.legislation.gov.uk/ukpga/1979/54/section/20" in urls
    mixed = official_page_urls(
        "https://www.legislation.gov.uk/ukpga/1981/54/section/31 ; https://www.justice.gov.uk/courts/procedure-rules/civil/rules/part54",
        "SCA 1981 s 31(3); CPR r 54.5(1)",
        "Senior Courts Act 1981 and Civil Procedure Rules",
    )
    assert "https://www.legislation.gov.uk/ukpga/1981/54/section/31" in mixed
    assert any(item.endswith("/rule/54.5") for item in mixed)
    assert all("justice.gov.uk" not in item for item in mixed)
    cpr_schedule = official_page_urls(
        "https://www.legislation.gov.uk/uksi/1998/3132/schedule/1",
        "r 31.7(1)",
        "Civil Procedure Rules 1998",
    )
    assert cpr_schedule == ["https://www.legislation.gov.uk/uksi/1998/3132/rule/31.7"]
    assert locator_covers("rule 54.5", "r 54.5(1)")
    assert locator_key("rule 54.5").startswith("r 54")
