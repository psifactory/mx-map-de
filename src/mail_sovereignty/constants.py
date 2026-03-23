import re

MICROSOFT_KEYWORDS = [
    "mail.protection.outlook.com",
    "outlook.com",
    "microsoft",
    "office365",
    "onmicrosoft",
    "spf.protection.outlook.com",
    "sharepointonline",
]
GOOGLE_KEYWORDS = [
    "google",
    "googlemail",
    "gmail",
    "_spf.google.com",
    "aspmx.l.google.com",
]
AWS_KEYWORDS = ["amazonaws", "amazonses", "awsdns"]
IONOS_KEYWORDS = ["ionos", "1and1", "schlund", "ui-dns", "perfora.net", "kundenserver.de"]
STRATO_KEYWORDS = ["strato"]
HETZNER_KEYWORDS = ["hetzner", "your-server.de"]
TELEKOM_KEYWORDS = ["t-online", "telekom", "mms.t-online.de"]
POSTEO_KEYWORDS = ["posteo"]
MAILBOX_ORG_KEYWORDS = ["mailbox.org"]
TUTANOTA_KEYWORDS = ["tutanota", "tutamail", "tuta.io"]
OPEN_XCHANGE_KEYWORDS = ["open-xchange"]

KOMMUNAL_KEYWORDS = [
    "kvnbw.de", "rlp.de", "landsh.de", "bayern.de", "pzd-svn.de",
    "mvnet.de", "kdo.de", "ekom21.de", "itebo.de", "regioit",
    "sis-schwerin", "kommunale.it", "kdvz", "civitec",
    "nol-is", "krz.de", "kgrz",
    "verwaltungsportal.de", "cm-system.de", "kdgoe.de", "rechennetz.de",
    "kis-asp.de", "ennit.net", "owis365.de",
]

MANAGED_HOSTING_KEYWORDS = [
    "agenturserver.de", "kasserver.com", "ispgateway.de", "all-inkl",
    "goneo.de", "udag.de", "next-go.net", "one.com", "kraemer-it",
    "ktk.de", "secureserver.net", "rzone.de",
]

WEBSITE_BUILDER_KEYWORDS = [
    "jimdo.com", "wix.com", "squarespace", "weebly",
]

VISIBLE_GATEWAYS = {
    "hornetsecurity", "sophos", "barracuda", "proofpoint",
    "antispameurope", "mimecast",
}

PROVIDER_KEYWORDS = {
    "microsoft": MICROSOFT_KEYWORDS,
    "google": GOOGLE_KEYWORDS,
    "aws": AWS_KEYWORDS,
    "ionos": IONOS_KEYWORDS,
    "strato": STRATO_KEYWORDS,
    "hetzner": HETZNER_KEYWORDS,
    "telekom": TELEKOM_KEYWORDS,
    "posteo": POSTEO_KEYWORDS,
    "mailbox.org": MAILBOX_ORG_KEYWORDS,
    "tutanota": TUTANOTA_KEYWORDS,
    "open-xchange": OPEN_XCHANGE_KEYWORDS,
}

FOREIGN_SENDER_KEYWORDS = {
    "mailchimp": ["mandrillapp.com", "mandrill", "mcsv.net"],
    "sendgrid": ["sendgrid"],
    "mailjet": ["mailjet"],
    "mailgun": ["mailgun"],
    "brevo": ["sendinblue", "brevo"],
    "mailchannels": ["mailchannels"],
    "smtp2go": ["smtp2go"],
    "nl2go": ["nl2go"],
    "hubspot": ["hubspotemail"],
    "knowbe4": ["knowbe4"],
    "hornetsecurity": ["hornetsecurity", "hornetdmarc"],
}

SPARQL_URL = "https://query.wikidata.org/sparql"
SPARQL_QUERY = """
SELECT ?item ?itemLabel ?ags ?website ?stateLabel ?coord WHERE {
  ?item wdt:P31/wdt:P279* wd:Q262166 .   # instance of (or subclass of) municipality of Germany
  ?item wdt:P439 ?ags .                   # official municipality key (AGS / Gemeindeschluessel)
  FILTER NOT EXISTS {                      # exclude dissolved municipalities
    ?item wdt:P576 ?dissolved .
    FILTER(?dissolved <= NOW())
  }
  FILTER NOT EXISTS {                      # exclude municipalities replaced by a successor
    ?item wdt:P1366 ?successor .
  }
  OPTIONAL { ?item wdt:P856 ?website . }
  OPTIONAL { ?item wdt:P131 ?state .
             ?state wdt:P31 wd:Q1221156 . }
  OPTIONAL { ?item wdt:P625 ?coord . }
  SERVICE wikibase:label { bd:serviceParam wikibase:language "de,en" . }
}
ORDER BY ?ags
"""

SPARQL_QUERY_COUNTIES = """
SELECT ?item ?itemLabel ?ags ?website ?stateLabel ?coord ?typeLabel WHERE {
  VALUES ?type { wd:Q106658 wd:Q22865 }
  ?item wdt:P31/wdt:P279* ?type .
  ?item wdt:P440 ?ags .                   # district key (Kreisschlüssel)
  FILTER NOT EXISTS {
    ?item wdt:P576 ?dissolved .
    FILTER(?dissolved <= NOW())
  }
  FILTER NOT EXISTS {
    ?item wdt:P1366 ?successor .
  }
  OPTIONAL { ?item wdt:P856 ?website . }
  OPTIONAL { ?item wdt:P131 ?state .
             ?state wdt:P31 wd:Q1221156 . }
  OPTIONAL { ?item wdt:P625 ?coord . }
  SERVICE wikibase:label { bd:serviceParam wikibase:language "de,en" . }
}
ORDER BY ?ags
"""

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
TYPO3_RE = re.compile(r"linkTo_UnCryptMailto\(['\"]([^'\"]+)['\"]")
SKIP_DOMAINS = {
    "example.com",
    "example.de",
    "sentry.io",
    "w3.org",
    "gstatic.com",
    "googleapis.com",
    "schema.org",
}

SUBPAGES = [
    "/kontakt",
    "/impressum",
    "/kontakt/",
    "/impressum/",
    "/de/kontakt",
    "/verwaltung",
    "/rathaus",
    "/buergerservice",
    "/gemeinde",
    "/stadt",
    "/stadtverwaltung",
    "/gemeindeverwaltung",
    "/ansprechpartner",
]

GATEWAY_KEYWORDS = {
    "seppmail": ["seppmail.cloud", "seppmail.com"],
    "barracuda": ["barracudanetworks.com", "barracuda.com"],
    "trendmicro": ["tmes.trendmicro.eu", "tmes.trendmicro.com"],
    "hornetsecurity": ["hornetsecurity.com"],
    "proofpoint": ["ppe-hosted.com", "proofpoint.com"],
    "sophos": ["hydra.sophos.com", "sophos.com"],
    "mimecast": ["mimecast.com"],
    "retarus": ["retarus.com", "retarus.de"],
    "nospamproxy": ["nospamproxy"],
    "antispameurope": ["antispameurope.com"],
}

GERMAN_ISP_ASNS: dict[int, str] = {
    3320: "Deutsche Telekom",
    6724: "Strato",
    6805: "Telefonica / O2",
    8560: "IONOS / 1&1",
    8972: "Host Europe / PlusServer",
    12897: "Hetzner",
    13335: "Cloudflare",
    24940: "Hetzner Online",
    29551: "STRATO",
    31334: "Kabel Deutschland / Vodafone",
    48314: "Michael Sapper (IP-Projects)",
    51167: "Contabo",
    197540: "netcup",
}

DKIM_SELECTORS = [
    "google",
    "selector1",
    "selector2",
    "default",
    "dkim",
    "s1",
    "s2",
    "k1",
    "mail",
    "mta",
]

CONCURRENCY = 20
CONCURRENCY_POSTPROCESS = 10
CONCURRENCY_SMTP = 5
CONCURRENCY_WEBSITE = 20

# --- Website Hosting Provider ASN mapping ---
HOSTING_PROVIDER_ASNS: dict[int, str] = {
    13335: "cloudflare",
    16509: "aws",
    14618: "aws",
    15169: "google-cloud",
    396982: "google-cloud",
    8075: "azure",
    8068: "azure",
    16276: "ovh",
    24940: "hetzner",
    12897: "hetzner",
    8560: "ionos",
    6724: "strato",
    29551: "strato",
    197540: "netcup",
    35366: "all-inkl",
    34788: "mittwald",
    8972: "host-europe",
    3320: "telekom",
    51167: "contabo",
}

HOSTING_PROVIDER_LABELS: dict[str, str] = {
    "cloudflare": "Cloudflare",
    "aws": "AWS",
    "google-cloud": "Google Cloud",
    "azure": "Azure",
    "ovh": "OVH",
    "hetzner": "Hetzner",
    "ionos": "IONOS",
    "strato": "Strato",
    "netcup": "netcup",
    "all-inkl": "ALL-INKL",
    "mittwald": "Mittwald",
    "host-europe": "Host Europe",
    "telekom": "Telekom",
    "contabo": "Contabo",
    "kommunal-rz": "Kommunales RZ",
}

# --- CMS Detection Patterns ---
CMS_HEADER_PATTERNS: dict[str, list[str]] = {
    "wordpress": ["wordpress"],
    "typo3": ["typo3"],
    "joomla": ["joomla"],
    "drupal": ["drupal"],
    "jimdo": ["jimdo"],
    "wix": ["wix"],
    "squarespace": ["squarespace"],
    "shopify": ["shopify"],
}

CMS_URL_PATTERNS: dict[str, list[str]] = {
    "wordpress": ["/wp-content/", "/wp-includes/", "/wp-json/"],
    "typo3": ["/typo3conf/", "/typo3temp/", "/typo3/"],
    "joomla": ["/components/com_", "/media/jui/"],
    "drupal": ["/sites/default/files/", "/core/misc/drupal"],
}

# --- Analytics/Tracker Detection Patterns ---
TRACKER_PATTERNS: dict[str, list[str]] = {
    "google-analytics": [
        "googletagmanager.com", "google-analytics.com",
        "gtag(", "UA-", "G-", "ga('send",
    ],
    "google-tag-manager": ["googletagmanager.com/gtm.js"],
    "facebook-pixel": ["connect.facebook.net", "fbq("],
    "matomo": ["matomo.js", "matomo.php", "piwik.js", "piwik.php"],
    "plausible": ["plausible.io"],
    "etracker": ["etracker.com", "etracker.de"],
}

# --- Cookie Consent Detection Patterns ---
CONSENT_PATTERNS: dict[str, list[str]] = {
    "cookiebot": ["cookiebot.com", "CookieConsent"],
    "usercentrics": ["usercentrics.eu", "usercentrics.com"],
    "borlabs": ["borlabs-cookie", "BorlabsCookie"],
    "onetrust": ["onetrust.com", "optanon"],
    "klaro": ["klaro.js", "klaro.kiprotect"],
}

SMTP_BANNER_KEYWORDS = {
    "microsoft": [
        "microsoft esmtp mail service",
        "outlook.com",
        "protection.outlook.com",
    ],
    "google": [
        "mx.google.com",
        "google esmtp",
    ],
    "ionos": [
        "kundenserver.de",
        "1and1",
        "ionos",
    ],
    "strato": [
        "strato",
    ],
    "hetzner": [
        "hetzner",
        "your-server.de",
    ],
    "aws": [
        "amazonaws",
        "amazonses",
    ],
}
