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
    "proofpoint": ["ppe-hosted.com"],
    "sophos": ["hydra.sophos.com"],
    "mimecast": ["mimecast.com"],
    "retarus": ["retarus.com", "retarus.de"],
    "nospamproxy": ["nospamproxy"],
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

CONCURRENCY = 20
CONCURRENCY_POSTPROCESS = 10
CONCURRENCY_SMTP = 5

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
