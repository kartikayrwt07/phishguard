"""
Curated URL Dataset Generator and Management for PhishGuard ML Pipeline.
Generates balanced, categorized legitimate and phishing URLs with registered domain (eTLD+1) keys.
"""
import os
import random
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pandas as pd

# Ensure backend modules can be imported
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
BACKEND_DIR = PROJECT_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.detection.url_parser import URLNormalizer


DEFAULT_RAW_PATH = PROJECT_ROOT / "ml" / "data" / "raw" / "urls_raw.csv"
DEFAULT_PROCESSED_PATH = PROJECT_ROOT / "ml" / "data" / "processed" / "urls_processed.csv"


LEGITIMATE_DOMAINS = [
    # Search & Technology
    ("google.com", "tech", ["/search?q=cybersecurity", "/maps", "/intl/en/about", "/drive"]),
    ("microsoft.com", "tech", ["/en-us/windows", "/en-us/security", "/edge", "/support"]),
    ("apple.com", "tech", ["/iphone", "/mac", "/support", "/app-store"]),
    ("github.com", "tech", ["/features", "/pricing", "/explore", "/trending"]),
    ("stackoverflow.com", "tech", ["/questions", "/tags", "/users", "/jobs"]),
    ("wikipedia.org", "education", ["/wiki/Computer_security", "/wiki/Phishing", "/wiki/TLS"]),
    ("mozilla.org", "tech", ["/en-US/firefox/new", "/en-US/privacy", "/en-US/about"]),
    ("cloudflare.com", "tech", ["/learning/ddos/what-is-a-ddos-attack", "/products", "/plans"]),
    ("amazon.com", "ecommerce", ["/gp/bestsellers", "/orders", "/prime", "/customer-service"]),
    ("netflix.com", "media", ["/browse", "/login", "/your-account", "/help"]),
    ("spotify.com", "media", ["/us/premium", "/us/download", "/us/account"]),
    ("zoom.us", "tech", ["/meetings", "/pricing", "/download", "/signin"]),
    ("slack.com", "tech", ["/features", "/pricing", "/help", "/apps"]),
    ("linkedin.com", "social", ["/in/security-engineer", "/jobs", "/feed", "/learning"]),
    ("youtube.com", "media", ["/feed/subscriptions", "/trending", "/watch?v=dQw4w9WgXcQ"]),

    # Banking & Finance
    ("chase.com", "finance", ["/personal/banking", "/credit-cards", "/online-banking", "/contact-us"]),
    ("bankofamerica.com", "finance", ["/deposits", "/credit-cards", "/security-center"]),
    ("wellsfargo.com", "finance", ["/help/security", "/investing", "/checking"]),
    ("paypal.com", "finance", ["/us/signin", "/us/security", "/us/business"]),
    ("stripe.com", "finance", ["/docs/api", "/pricing", "/customers", "/payments"]),
    ("fidelity.com", "finance", ["/trading/overview", "/mutual-funds", "/customer-service"]),

    # News & Media
    ("nytimes.com", "news", ["/section/technology", "/section/world", "/section/business"]),
    ("bbc.co.uk", "news", ["/news/technology", "/news/world", "/sport"]),
    ("theguardian.com", "news", ["/technology", "/business", "/world"]),
    ("reuters.com", "news", ["/technology", "/business/finance", "/markets"]),

    # Government & Education
    ("irs.gov", "gov", ["/payments", "/refunds", "/forms-instructions"]),
    ("usa.gov", "gov", ["/benefits", "/taxes", "/identity-theft"]),
    ("mit.edu", "education", ["/research", "/education", "/admissions"]),
    ("harvard.edu", "education", ["/academics", "/programs", "/admissions"]),
    ("stanford.edu", "education", ["/academics", "/research", "/admission"]),
]


PHISHING_PATTERNS = [
    # Homoglyphs & Lookalikes
    ("paypa1-security.xyz", "homoglyph", ["/signin.php", "/verify-account", "/confirm?id=92841"]),
    ("app1e-id-recovery.top", "homoglyph", ["/auth/login", "/security/checkpoint", "/unlock"]),
    ("micros0ft-online.club", "homoglyph", ["/o365/login", "/ad/authenticate", "/portal/verify"]),
    ("g00gle-accounts.space", "homoglyph", ["/signin/v2/identifier", "/challenge/pwd"]),
    ("amaz0n-prime-reward.fit", "homoglyph", ["/claim-gift", "/billing/card-update", "/account-alert"]),
    ("wellsfarg0-support.loan", "homoglyph", ["/online/signon", "/identity/verify", "/security"]),

    # Typosquats & Keyword Stuffing
    ("chasee-online-portal.work", "typosquat", ["/auth/signin", "/account-verification", "/step2"]),
    ("netflixx-billing-update.click", "typosquat", ["/youraccount", "/payment-declined", "/update-card"]),
    ("bofa-account-verification.review", "compound", ["/portal/login.htm", "/auth/step1", "/confirm"]),
    ("paypal-resolution-center.xyz", "compound", ["/cgi-bin/webscr?cmd=_login-run", "/dispute/case"]),
    ("appleid-support-recover.top", "compound", ["/manage/login", "/identity/2fa-bypass"]),
    ("microsoft-security-auth.gq", "compound", ["/common/oauth2/authorize", "/login.srf"]),
    ("chase-fraud-prevention.buzz", "compound", ["/verify/identity", "/card-holder/confirm"]),
    ("stripe-invoicing-service.site", "compound", ["/invoice/pay?ref=91823", "/session/checkout"]),

    # Subdomain Spoofing
    ("paypal.com.verify-credentials.xyz", "subdomain_spoof", ["/cgi-bin/signin", "/webscr", "/login"]),
    ("appleid.apple.com.account-recovery.top", "subdomain_spoof", ["/manage", "/signin", "/unlock"]),
    ("login.microsoftonline.com.auth-token.party", "subdomain_spoof", ["/oauth/token", "/v2.0/auth"]),
    ("secure.chase.com.banking-alert.club", "subdomain_spoof", ["/auth/logon", "/verify", "/security"]),
    ("signin.ebay.com.dispute-center.work", "subdomain_spoof", ["/ws/eBayISAPI.dll", "/account"]),

    # IP Host Destinations
    ("192.168.1.100", "ip_host", ["/login.php", "/admin/auth", "/webmail/login"]),
    ("198.51.100.45", "ip_host", ["/portal/secure", "/bank/login", "/verify-identity"]),
    ("203.0.113.88", "ip_host", ["/online-banking/index.html", "/auth/login.jsp", "/signin"]),
    ("185.220.101.5", "ip_host", ["/update-payment", "/account/suspended", "/checkout"]),

    # Non-standard ports & Obfuscated credentials
    ("secure-banking-portal.top:8080", "non_standard_port", ["/ebanking/login", "/auth/sso"]),
    ("account-recovery-system.xyz:8443", "non_standard_port", ["/verify", "/confirm-ssn"]),
    ("quick-verify-id.click:9000", "non_standard_port", ["/portal/login", "/challenge"]),
    ("crypto-reward-claim.buzz", "credential_harvest", ["/claim-airdrop", "/connect-wallet", "/seed-phrase"]),
]


def generate_curated_samples() -> List[Dict[str, any]]:
    """Build base curated list of legitimate and phishing samples."""
    samples: List[Dict[str, any]] = []

    # 1. Legitimate URLs
    for domain, category, paths in LEGITIMATE_DOMAINS:
        parsed = URLNormalizer.parse(f"https://{domain}")
        reg_domain = parsed.registered_domain or domain

        for path in paths:
            url = f"https://www.{domain}{path}" if not domain.startswith("www.") else f"https://{domain}{path}"
            samples.append({
                "url": url,
                "label": 0,
                "category": f"legitimate_{category}",
                "domain": reg_domain,
            })

    # 2. Phishing URLs
    for host_or_domain, category, paths in PHISHING_PATTERNS:
        parsed = URLNormalizer.parse(f"http://{host_or_domain}")
        reg_domain = parsed.registered_domain or host_or_domain.split(":")[0]

        for path in paths:
            scheme = "http" if "192." in host_or_domain or "198." in host_or_domain or "203." in host_or_domain or "185." in host_or_domain else "https"
            url = f"{scheme}://{host_or_domain}{path}"
            samples.append({
                "url": url,
                "label": 1,
                "category": f"phishing_{category}",
                "domain": reg_domain,
            })

    return samples


def generate_dataset(
    target_size: int = 500,
    random_state: int = 42,
) -> pd.DataFrame:
    """
    Generate a balanced, deduplicated dataset with domain-level grouping keys.
    target_size: Desired total number of samples (half legitimate, half phishing).
    """
    rng = random.Random(random_state)
    base_samples = generate_curated_samples()

    legit_base = [s for s in base_samples if s["label"] == 0]
    phish_base = [s for s in base_samples if s["label"] == 1]

    target_per_class = target_size // 2

    # Procedural variations for expanding legitimate samples
    query_params = ["ref=nav", "lang=en", "session_id=abc", "source=web", "page=1", "mode=desktop"]
    expanded_legit = list(legit_base)
    idx = 0
    while len(expanded_legit) < target_per_class:
        base = legit_base[idx % len(legit_base)]
        param = rng.choice(query_params)
        sep = "&" if "?" in base["url"] else "?"
        variant_url = f"{base['url']}{sep}{param}_{rng.randint(100, 9999)}"
        expanded_legit.append({
            "url": variant_url,
            "label": 0,
            "category": base["category"],
            "domain": base["domain"],
        })
        idx += 1

    # Procedural variations for expanding phishing samples
    phish_suffixes = [
        "account_id=", "token=", "auth_key=", "redirect_uri=https://safe.com",
        "email=victim%40example.com", "step=confirm_billing", "action=verify"
    ]
    expanded_phish = list(phish_base)
    idx = 0
    while len(expanded_phish) < target_per_class:
        base = phish_base[idx % len(phish_base)]
        suffix = rng.choice(phish_suffixes)
        sep = "&" if "?" in base["url"] else "?"
        variant_url = f"{base['url']}{sep}{suffix}{rng.randint(1000, 99999)}"
        expanded_phish.append({
            "url": variant_url,
            "label": 1,
            "category": base["category"],
            "domain": base["domain"],
        })
        idx += 1

    all_samples = expanded_legit[:target_per_class] + expanded_phish[:target_per_class]
    rng.shuffle(all_samples)

    df = pd.DataFrame(all_samples)
    # Deduplicate by URL
    df = df.drop_duplicates(subset=["url"]).reset_index(drop=True)

    # Ensure registered domain is extracted consistently
    df["domain"] = df["url"].apply(lambda u: URLNormalizer.parse(u).registered_domain or URLNormalizer.parse(u).host)

    return df


def save_dataset(df: pd.DataFrame, filepath: Optional[Path] = None) -> Path:
    """Save dataset DataFrame to CSV."""
    path = filepath or DEFAULT_PROCESSED_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(path, index=False)
    return path


def load_dataset(filepath: Optional[Path] = None) -> pd.DataFrame:
    """Load dataset DataFrame from CSV, generating default if not present."""
    path = filepath or DEFAULT_PROCESSED_PATH
    if not path.exists():
        df = generate_dataset()
        save_dataset(df, path)
        return df
    return pd.read_csv(path)
