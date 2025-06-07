import re
import socket
import tldextract
from urllib.parse import urlparse
import whois
import requests
from bs4 import BeautifulSoup
import math
from collections import Counter

# Helper function to check if the hostname is an IP address
def is_ip(address):
    try:
        socket.inet_aton(address)
        return True
    except:
        return False

# Shannon entropy for detecting randomness in domain names
def shannon_entropy(domain):
    prob = [freq / len(domain) for freq in Counter(domain).values()]
    return -sum(p * math.log2(p) for p in prob if p > 0)

# Extract HTML-based features
def extract_html_features(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.content, 'html.parser')

        nb_hyperlinks = len(soup.find_all('a'))
        nb_ext_hyperlinks = sum(
            1 for link in soup.find_all('a', href=True)
            if urlparse(link['href']).netloc and urlparse(link['href']).netloc != urlparse(url).netloc
        )
        iframe_count = len(soup.find_all('iframe'))
        nb_media = len(soup.find_all(['img', 'audio', 'video']))
        login_form = 1 if soup.find_all('form') and soup.find_all('input') else 0
        onmouseover = 1 if soup.find_all(attrs={'onmouseover': True}) else 0
        right_clic = 1 if soup.find_all(attrs={'oncontextmenu': True}) else 0

        return nb_hyperlinks, nb_ext_hyperlinks, iframe_count, nb_media, login_form, onmouseover, right_clic

    except requests.exceptions.RequestException:
        return 0, 0, 0, 0, 0, 0, 0

# Main feature extraction function
def extract_features(url):
    features = {}

    parsed = urlparse(url)
    ext = tldextract.extract(url)
    domain = ext.domain
    subdomain = ext.subdomain
    suffix = ext.suffix
    hostname = parsed.hostname or ''
    path = parsed.path

    # Basic lexical features
    features['length_url'] = len(url)
    features['length_hostname'] = len(hostname)
    features['ip'] = 1 if is_ip(hostname) else 0
    features['nb_dots'] = url.count('.')
    features['nb_hyphens'] = url.count('-')
    features['nb_at'] = url.count('@')
    features['nb_qm'] = url.count('?')
    features['nb_and'] = url.count('&')
    features['nb_or'] = url.lower().count(' or ')
    features['nb_eq'] = url.count('=')
    features['nb_underscore'] = url.count('_')
    features['nb_tilde'] = url.count('~')
    features['nb_percent'] = url.count('%')
    features['nb_slash'] = url.count('/')
    features['nb_star'] = url.count('*')
    features['nb_colon'] = url.count(':')
    features['nb_comma'] = url.count(',')
    features['nb_semicolumn'] = url.count(';')
    features['nb_dollar'] = url.count('$')
    features['nb_space'] = url.count(' ')
    features['nb_www'] = url.lower().count('www')
    features['nb_com'] = url.lower().count('.com')
    features['nb_dslash'] = url.count('//') - 1
    features['http_in_path'] = int('http' in path.lower())
    features['https_token'] = int('https' in url.lower() and not url.startswith('https'))
    features['ratio_digits_url'] = sum(c.isdigit() for c in url) / len(url) if len(url) > 0 else 0
    features['ratio_digits_host'] = sum(c.isdigit() for c in hostname) / len(hostname) if hostname else 0
    features['punycode'] = int('xn--' in hostname)
    features['port'] = 1 if parsed.port else 0
    features['tld_in_path'] = int(suffix in path)
    features['tld_in_subdomain'] = int(suffix in subdomain)
    features['abnormal_subdomain'] = int(len(subdomain.split('.')) > 3)
    features['nb_subdomains'] = len(subdomain.split('.')) if subdomain else 0
    features['prefix_suffix'] = int('-' in domain)

    features['random_domain'] = int(shannon_entropy(domain) > 3.5)
    features['shortening_service'] = int(re.search(
        r"(bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|yfrog\.com|migre\.me|ff\.im|tiny\.cc)",
        url) is not None)

    features['path_extension'] = int(bool(re.search(r'\.\w{2,4}$', path)))
    features['nb_redirection'] = 0
    features['nb_external_redirection'] = 0

    raw_words = re.split(r'\W+', url)
    host_words = re.split(r'\W+', hostname)
    path_words = re.split(r'\W+', path)

    features['length_words_raw'] = sum(len(w) for w in raw_words if w)
    features['char_repeat'] = max((raw_words.count(w) for w in raw_words if w), default=0)
    features['shortest_words_raw'] = min((len(w) for w in raw_words if w), default=0)
    features['shortest_word_host'] = min((len(w) for w in host_words if w), default=0)
    features['shortest_word_path'] = min((len(w) for w in path_words if w), default=0)
    features['longest_words_raw'] = max((len(w) for w in raw_words if w), default=0)
    features['longest_word_host'] = max((len(w) for w in host_words if w), default=0)
    features['longest_word_path'] = max((len(w) for w in path_words if w), default=0)
    features['avg_words_raw'] = sum(len(w) for w in raw_words if w) / len(raw_words) if raw_words else 0
    features['avg_word_host'] = sum(len(w) for w in host_words if w) / len(host_words) if host_words else 0
    features['avg_word_path'] = sum(len(w) for w in path_words if w) / len(path_words) if path_words else 0

    phishing_keywords = ['secure', 'account', 'update', 'free', 'login', 'signin', 'banking', 'ebay', 'paypal']
    features['phish_hints'] = sum(1 for kw in phishing_keywords if kw in url.lower())

    features['domain_in_brand'] = 0
    features['brand_in_subdomain'] = 0
    features['brand_in_path'] = 0
    suspicious_tlds = ['zip', 'review', 'country', 'kim', 'cricket', 'science', 'work']
    features['suspecious_tld'] = int(suffix in suspicious_tlds)

    features['statistical_report'] = 0

    nb_hyperlinks, nb_ext_hyperlinks, iframe_count, nb_media, login_form, onmouseover, right_clic = extract_html_features(url)
    features['nb_hyperlinks'] = nb_hyperlinks
    features['ratio_intHyperlinks'] = 0.5
    features['ratio_extHyperlinks'] = nb_ext_hyperlinks / nb_hyperlinks if nb_hyperlinks > 0 else 0
    features['ratio_nullHyperlinks'] = 0
    features['nb_extHyperlinks'] = nb_ext_hyperlinks
    features['nb_extCSS'] = 0
    features['ratio_intRedirection'] = 0.0
    features['ratio_extRedirection'] = 0.0
    features['ratio_intErrors'] = 0.0
    features['ratio_extErrors'] = 0.0
    features['login_form'] = login_form
    features['external_favicon'] = 0
    features['links_in_tags'] = 0.0
    features['submit_email'] = 0
    features['ratio_intMedia'] = 0.5
    features['ratio_extMedia'] = 0.5
    features['sfh'] = 0
    features['popup_window'] = 0
    features['safe_anchor'] = 0.5
    features['onmouseover'] = onmouseover
    features['right_clic'] = right_clic
    features['empty_title'] = 0
    features['domain_in_title'] = 0
    features['domain_with_copyright'] = 0

    try:
        domain_info = whois.whois(hostname)
        features['whois_registered_domain'] = int(domain_info.domain_name is not None)
        if domain_info.creation_date and domain_info.expiration_date:
            age = (domain_info.expiration_date - domain_info.creation_date).days
            features['domain_registration_length'] = age
        else:
            features['domain_registration_length'] = -1
    except:
        features['whois_registered_domain'] = 0
        features['domain_registration_length'] = -1

    features['domain_age'] = 100
    features['web_traffic'] = 0
    features['dns_record'] = 1
    features['google_index'] = 1
    features['page_rank'] = 1

    assert len(features) == 87, f"Expected 87 features, got {len(features)}"

    return list(features.values())
