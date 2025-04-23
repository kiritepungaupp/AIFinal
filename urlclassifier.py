import tldextract
import re
from urllib.parse import urlparse,parse_qs
import labels
import sqlite3
import datetime
import whois
import math
from collections import Counter

def get_tld(url):
    ext = tldextract.extract(url).suffix
    return ext

# url = "https://www.example.com"
# tld = get_tld(url)
# print(f'TLD: {tld}')

def url_entropy(url):
    if not url:
        return 0.0
    counter = Counter(url)
    total_length = len(url)
    entropy = -sum((count / total_length) * math.log2(count / total_length)
                   for count in counter.values())
    return round(entropy, 4)

def check_domain_age(domain):
    conn = sqlite3.connect("age_domain.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS domain_age (
            domain TEXT PRIMARY KEY,
            age INTEGER,
            last_checked TIMESTAMP
        )
    """)
    conn.commit()
    cursor.execute("SELECT age FROM domain_age WHERE domain = ?", (domain,))
    row = cursor.fetchone()
    if row:
        return row[0]
    
    try:
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        age = (datetime.datetime.now() - created).days  if created else 1
    except:
        age = 1
    cursor.execute("INSERT OR REPLACE INTO domain_age (domain, age, last_checked) VALUES (?, ?, ?)",
                   (domain, age, datetime.datetime.now()))
    conn.commit()
    return age


def build_url(url:str):

    login_keywords = ['login', 'signin', 'logon', 'account', 'auth', 'verify', 'access', 'credential', 'session']
    financial_keywords = ['bank', 'paypal', 'securepay', 'transfer', 'invoice', 'payment', 'wallet', 'credit', 'debit', 'checkout']
    technical_keywords = ['update', 'install', 'patch', 'setup', 'server', 'root', 'admin', 'exe', 'download', 'bin']
    social_keywords = ['free', 'win', 'offer', 'urgent', 'now', 'click', 'bonus', 'alert', 'limited', 'important']


    if not url.startswith(('http://', 'https://')):
        hturl = 'http://' + url
    else:
        hturl = url

    parsed = urlparse(hturl)
    netloc = parsed.netloc

    tags = []
    tags.append(sum(url.lower().count(k) for k in login_keywords))
    tags.append(sum(url.lower().count(k) for k in financial_keywords))
    tags.append(sum(url.lower().count(k) for k in technical_keywords))
    tags.append(sum(url.lower().count(k) for k in social_keywords))
    tags.append(1) if bool(re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', url))  else tags.append(0)
    tags.append(1) if bool(re.search(r'\b(?:bit\.ly|t\.co|goo\.gl|tinyurl\.com|ow\.ly|buff\.ly|is\.gd|j\.mp|tr\.im|dlvr\.it)\b', url, re.IGNORECASE)) else tags.append(0)
    tags.append(len(url))
    tags.append(url.count('.'))
    tags.append(url.count('%'))
    tags.append(url.count('-'))
    tags.append(url.count('@'))
    tags.append(url.count('#'))
    tags.append(url.count(';'))
    tags.append(url.count('_'))
    tags.append(url.count("?"))
    tags.append(url.count('='))
    tags.append(url.count('&'))
    tags.append(sum(1 for char in url if char.isalpha()))
    tags.append(sum(1 for char in url if char.isdigit()))
    tags.append(len(urlparse(hturl).path)-1)
    tags.append(url.count('/'))
    tags.append(urlparse(hturl).path.count('0'))
    tags.append(urlparse(hturl).path.count('%'))
    tags.append(len(re.findall(r'[a-z]', url.split('?')[0].split('#')[0])))
    tags.append(len(re.findall(r'[A-Z]', url.split('?')[0].split('#')[0])))
    tags.append(1 if any(len(dir) == 1 for dir in url.strip('/').split('/')) else 0)
    tags.append(int(any(dir.isupper() for dir in urlparse(url).path.strip('/').split('/'))))
    tags.append(len(urlparse(url).query))
    tags.append(len(parse_qs(urlparse(url).query)))
    tags.append(len(urlparse(url).netloc))
    tags.append((urlparse(url).netloc).count('-'))
    tags.append((urlparse(url).netloc).count('@'))
    tags.append(sum(1 for char in (urlparse(url).netloc) if not char.isalnum()))
    tags.append(sum(1 for char in (urlparse(url).netloc) if char.isdigit()))
    tags.append(len(get_tld(url)))
    tags.append(labels.getlabel(get_tld(url)))
    tags.append(check_domain_age(url))
    subdomain_depth = len(netloc.split('.')) - 2  # Assume 2 parts: main domain and TLD
    tags.append(subdomain_depth)
    tags.append(url_entropy(url))
    suspicious_extensions = ['.exe', '.apk', '.php', '.sh', '.bat', '.js', '.dll', '.msi']
    tags.append(sum(url.lower().endswith(ext) for ext in suspicious_extensions))
    tags.append(1 if ':' in urlparse(url).netloc else 0)



    return tags



columns = [
    'url_login_keyword', 'url_financial_keyword', 'url_technical_keyword', 
    'url_social_keyword', 'url_has_ip', 'url_isshorted', 'url_len', 'url_count_dot', 
    'url_count_perc', 'url_count_hyphen', 
    'url_count_atrate', 'url_count_hash', 'url_count_semicolon', 
    'url_count_underscore', 'url_count_ques', 'url_count_equal', 'url_count_amp', 
    'url_count_letter', 'url_count_digit',  
    'path_len', 
    'path_count_no_of_dir', 'path_count_zero', 
    'path_count_pertwent',  'path_count_lower', 
    'path_count_upper',  'path_has_singlechardir', 
    'path_has_upperdir', 'query_len', 'query_count_components', 'pdomain_len', 
    'pdomain_count_hyphen', 'pdomain_count_atrate', 'pdomain_count_non_alphanum', 
    'pdomain_count_digit', 'tld_len', 'tld', 'domain_age', 'subdomain_depth', 'url_entropy','suspicious_extensions', 'has_port' 
]

