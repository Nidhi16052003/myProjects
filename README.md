# myProjects
NVD data-NLP
import requests
from bs4 import BeautifulSoup
import re
import spacy

nlp = spacy.load("en_core_web_sm")


url = "https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query=apache&search_type=all&isCpeNameSearch=false"

response = requests.get(url)
soup = BeautifulSoup(response.text, "html.parser")


cve_links = soup.find_all("a", {"data-testid": lambda value: value and value.startswith("vuln-detail-link")})
cve_ids = [link.text.strip() for link in cve_links[:20]]
cvss_cell = row.select_one("td:nth-child(3)")
if cvss_cell:
    cvss_a_tag = cvss_cell.find("a")
    if cvss_a_tag:
        cvss_value = cvss_a_tag.get_text(strip=True)
    else:
        cvss_em_tag = cvss_cell.find("em")
        cvss_value = cvss_em_tag.next_sibling.strip() if cvss_em_tag and cvss_em_tag.next_sibling else "(no CVSS score)"
else:
    cvss_value = "(no CVSS score)"


paragraphs = soup.select('#row > table > tbody > tr > td:nth-child(2) > p')[:20]
next_words = []
fixed_versions = []
affected_versions = []
next_products = []

version_pattern = r"(\d+\.\d+\.\d+[-\.]?[A-Za-z0-9]*)(?:\s*(?:through|to)\s*(\d+\.\d+\.\d+[-\.]?[A-Za-z0-9]*))?"

def extract_versions(text):
    """Extract version numbers, including ranges (e.g., '1.10.0 through 1.27.0')."""
    return re.findall(version_pattern, text)

def format_version_range(versions):
    """Format version ranges to use 'to' between versions and 'and' between ranges."""
    formatted_ranges = []

    for version in versions:

        version = version.replace('through', 'to')

        formatted_ranges.append(version)

    return ' and '.join(formatted_ranges)


results = []

for i, paragraph in enumerate(paragraphs):

    if i >= len(cve_ids):
        break


    affected_versions = []
    fixed_versions = []

    text_content = paragraph.get_text(strip=True)
    words = text_content.split()


    doc = nlp(text_content)


    for sent in doc.sents:

        if "affects" in sent.text.lower():
            affected_versions += extract_versions(sent.text)


        if "upgrade" in sent.text.lower():
            fixed_versions += extract_versions(sent.text)


    if 'Apache' in words:
        apache_index = words.index('Apache')
        if apache_index + 1 < len(words):
            next_word = words[apache_index + 1]
        else:
            next_word = None
    else:
        next_word = None

    next_words.append(next_word)
    if next_word:
        next_products.append(next_word)
    else:
        next_products.append(None)
    formatted_affected_versions = format_version_range([f"{match[0]} to {match[1]}" if match[1] else match[0] for match in affected_versions])
    formatted_fixed_versions = format_version_range([f"{match[0]} to {match[1]}" if match[1] else match[0] for match in fixed_versions])
    results.append({
        "CVE ID": cve_ids[i],
        "Product": next_word,
        "Affected Version": formatted_affected_versions if affected_versions else "(no affected versions)",
        "Corrected Version": formatted_fixed_versions if fixed_versions else "(no fixed versions)",
        "CVSS Score": cvss_value

    })
import pandas as pd
df = pd.DataFrame(results)

df
