"""
Technology fingerprinting.

Fetches the homepage, then checks response headers, HTML markup,
script/link/img sources and cookie names against a signature table --
the same general idea as Wappalyzer, just with a smaller signature
set. Also reports which of the common security response headers are
present, since that's part of the attack surface too.
"""

import re

import requests
from bs4 import BeautifulSoup

from modules.request_helper import safe_get

REQUEST_TIMEOUT = 8
USER_AGENT = "ReconGuard/2.0 (authorized-recon)"

# category -> {tech name: [regex patterns checked against headers/html/asset urls/cookies]}
SIGNATURES = {
    "CMS": {
        "WordPress": [r"wp-content", r"wp-includes", r'generator" content="WordPress'],
        "Drupal": [r"drupal\.js", r'generator" content="Drupal', r"sites/default/files"],
        "Joomla": [r"/media/jui/", r'generator" content="Joomla'],
        "Wix": [r"wix\.com", r"wixstatic\.com"],
        "Squarespace": [r"squarespace\.com", r"static1\.squarespace\.com"],
        "Shopify": [r"cdn\.shopify\.com", r"Shopify\.theme"],
        "Ghost": [r'generator" content="Ghost'],
        "Webflow": [r"webflow\.js", r"assets\.website-files\.com"],
    },
    "JS Framework": {
        "React": [r"react-dom", r"__reactContainer", r"data-reactroot"],
        "Vue.js": [r"vue(\.min)?\.js", r"__vue__", r"data-v-"],
        "Angular": [r"ng-app", r"ng-controller", r"angular(\.min)?\.js", r"ng-version"],
        "Next.js": [r"__NEXT_DATA__", r"_next/static"],
        "Nuxt.js": [r"__NUXT__", r"_nuxt/"],
        "Svelte": [r"svelte-"],
        "jQuery": [r"jquery(\.min)?\.js"],
    },
    "CSS Framework": {
        "Bootstrap": [r"bootstrap(\.min)?\.css", r"bootstrap(\.min)?\.js"],
        "Tailwind CSS": [r"tailwind(\.min)?\.css"],
        "Foundation": [r"foundation(\.min)?\.css"],
        "Bulma": [r"bulma(\.min)?\.css"],
    },
    "Server": {
        "Nginx": [r"^nginx"],
        "Apache": [r"^apache"],
        "Microsoft-IIS": [r"^microsoft-iis"],
        "LiteSpeed": [r"^litespeed"],
        "Gunicorn": [r"^gunicorn"],
    },
    "Language / Runtime": {
        "PHP": [r"\.php(\?|$|\")", r"^php/"],
        "ASP.NET": [r"\.aspx", r"x-aspnet-version", r"__viewstate"],
        "Express (Node.js)": [r"^express"],
        "Django": [r"csrfmiddlewaretoken"],
        "Ruby on Rails": [r"authenticity_token", r"x-runtime"],
    },
    "CDN / Edge": {
        "Cloudflare": [r"cloudflare", r"__cfduid", r"cf-ray"],
        "Amazon CloudFront": [r"cloudfront\.net", r"x-amz-cf-id"],
        "Akamai": [r"akamai"],
        "Fastly": [r"fastly"],
    },
    "Analytics / Tracking": {
        "Google Analytics": [r"google-analytics\.com", r"gtag\(", r"googletagmanager\.com"],
        "Meta Pixel": [r"connect\.facebook\.net.*fbevents"],
        "Hotjar": [r"static\.hotjar\.com"],
        "Mixpanel": [r"cdn\.mxpnl\.com"],
    },
    "Ecommerce": {
        "WooCommerce": [r"woocommerce"],
        "Magento": [r"Mage\.Cookies", r"/static/version"],
        "PrestaShop": [r"prestashop"],
    },
}

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]


def _asset_urls(soup):
    urls = []
    for tag in soup.find_all(["script", "link", "img"]):
        src = tag.get("src") or tag.get("href")
        if src:
            urls.append(src)
    return urls


def fingerprint(domain):
    result = {
        "reachable": False,
        "detected": {},
        "server_header": None,
        "powered_by": None,
        "security_headers": {h: False for h in SECURITY_HEADERS},
        "cookies": [],
    }

    resp = None
    for scheme in ("https://", "http://"):
        try:
            resp = safe_get(f"{scheme}{domain}")
            break
        except requests.RequestException:
            resp = None
            continue

    if resp is None:
        return result

    result["reachable"] = True
    headers = {k.lower(): v for k, v in resp.headers.items()}
    result["server_header"] = headers.get("server")
    result["powered_by"] = headers.get("x-powered-by")
    result["cookies"] = list(resp.cookies.keys())

    for header in SECURITY_HEADERS:
        result["security_headers"][header] = header in headers

    html = resp.text or ""
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        soup = BeautifulSoup("", "html.parser")

    combined = "\n".join([
        html.lower(),
        " ".join(_asset_urls(soup)).lower(),
        str(headers).lower(),
        " ".join(result["cookies"]).lower(),
    ])

    for category, techs in SIGNATURES.items():
        matches = sorted({
            name for name, patterns in techs.items()
            if any(re.search(p, combined, re.IGNORECASE) for p in patterns)
        })
        if matches:
            result["detected"][category] = matches

    return result
