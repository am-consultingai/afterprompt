"""What a leaked credential lets someone do, and therefore what to rotate first.

"Rotate now" used to be ordered by how sure the scan was: live credentials first, then tier, then how many
files and occurrences. That answers "how confident are we", not "how much does this cost me". On a real scan
it opened with a search-API key and put an Azure Storage account key below it. A list of twenty is only
actionable if the first three are the right three.

Four ranks, worst first. Each says what someone holding the value can do, not what the value looks like:

    money    spend in your name: cloud accounts, model APIs, payment and messaging services
    data     reach stored data: storage keys, connection strings, databases
    access   act as you: OAuth secrets, private keys, source-control and workspace tokens
    service  one service, and nothing beyond it: search APIs, webhooks, analytics

A pattern's rank comes from its own name where its group holds a mix, and from the group otherwise. A live
credential that matched no pattern is ranked by the name of the variable it was stored under, because that is
all we know about it. Nothing else is guessed: an unrecognised credential ranks `service`, so it sorts last
rather than crowding out something we do understand.
"""
import re

from afterprompt.patterns import GROUPS, VENDORS

# Worst first. The order is the sort order of "Rotate now".
RANKS = ("money", "data", "access", "service")
ORDER = {r: i for i, r in enumerate(RANKS)}
DEFAULT = "service"
# Shown on the card, in her words rather than ours.
LABELS = {"money": "Can spend money", "data": "Can reach stored data", "access": "Can act as you",
          "service": "One service"}
NOTES = {
    "money": "Whoever has this can run up charges on the account that issued it.",
    "data": "Whoever has this can read, and usually change, what is stored there.",
    "access": "Whoever has this can act as you on that account or machine.",
    "service": "Limited to the one service that issued it.",
}

# Default per pattern group. Every group in patterns.json must appear here; a test enforces it, so renaming a
# group in the data file fails loudly instead of quietly demoting its patterns to "service".
GROUP_RANK = {
    "AI / LLM providers": "money",
    "Cloud": "money",
    "Microsoft / Azure formats": "data",
    "VCS / package registries": "access",
    "Keys / structural": "access",
    "private keys without PEM headers (base64 DER bodies)": "access",
    "structural: headers, cookies, CLI flags, URL params, prose": "access",
    "Comms / SaaS": "service",
    "Meta / WhatsApp / Google / registrars / payment + messaging": "service",
}

# Patterns whose group default is wrong for them. Grouping is by who issued a key; this is by what it opens.
NAME_RANK = {
    # Cloud, but the key opens storage rather than the account
    "azure_conn_string": "data", "azure_storage_key": "data", "azure_sas_signature": "data",
    "supabase_secret_key": "data", "supabase_service_key_ctx": "data",
    # Cloud, but the credential is an identity rather than a budget
    "azure_ad_client_secret": "access", "gcp_client_secret": "access", "gcp_oauth_access_token": "access",
    "gcp_oauth_refresh_token": "access", "google_oauth_auth_code": "access",
    "google_session_cookie_ctx": "access", "terraform_cloud_token": "access",
    # Azure formats that are identities, not storage
    "azure_devops_pat": "access", "azure_devops_pat_ctx": "access", "entra_client_secret": "access",
    "azure_function_key_url": "access",
    # Structural shapes that carry a database behind them
    "url_with_credentials": "data",
    # SaaS that bills, sends, or charges
    "stripe_secret_key": "money", "stripe_webhook_secret": "money", "square_token": "money",
    "twilio_ctx": "money", "twilio_api_key_sid": "money", "sendgrid_key": "money", "mailgun_key": "money",
    "mailchimp_key": "money", "postmark_ctx": "money", "resend_key": "money",
    "il_payment_ctx": "money", "whatsapp_gateway_ctx": "money",
    # SaaS that is really a datastore
    "airtable_key": "data", "shopify_token": "data", "salesforce_ctx": "data", "salesforce_session": "data",
    # SaaS where the token is you
    "slack_token": "access", "notion_token": "access", "atlassian_api_token": "access",
    "atlassian_ctx": "access", "linear_key": "access", "asana_pat": "access", "figma_token": "access",
    "sentry_token": "access", "discord_bot_token": "access", "telegram_bot_token": "access",
    "session_cookie_ctx": "access", "linkedin_cookie_bare": "access", "linkedin_li_at_ctx": "access",
    "meta_access_token": "access", "porkbun_api_key": "access", "registrar_dns_ctx": "access",
}

# A live credential with no pattern behind it is known only by the variable it was stored under. Data rules
# run first on purpose: AZURE_STORAGE_CONNECTION_STRING is storage, not spend, and both words are in it.
KEY_RANK = [
    (r"DATABASE|DB_(URL|PASS|USER|HOST)|POSTGRES|PGPASS|MYSQL|MARIADB|MONGO|REDIS|ELASTIC|CLICKHOUSE|"
     r"SNOWFLAKE|STORAGE|BLOB|BUCKET|^S3_|_S3_|AIRTABLE|SUPABASE|FIRESTORE|DYNAMO", "data"),
    (r"CLIENT_SECRET|OAUTH|REFRESH_TOKEN|SESSION|COOKIE|^JWT|_JWT|PRIVATE_KEY|SSH|DEPLOY_KEY|SIGNING|"
     r"GITHUB|GITLAB|BITBUCKET|NPM|PYPI|RUBYGEMS|DOCKER|JFROG|ARTIFACTORY|SLACK|NOTION|ATLASSIAN|JIRA|"
     r"CONFLUENCE|LINEAR|ASANA|FIGMA|SENTRY|DISCORD|TELEGRAM|SALESFORCE|TERRAFORM|KUBE", "access"),
    (r"^AWS|_AWS|AZURE|^GCP|GOOGLE|GEMINI|VERTEX|OPENAI|ANTHROPIC|CLAUDE|GROQ|XAI|GROK|OPENROUTER|MISTRAL|"
     r"COHERE|PERPLEXITY|REPLICATE|ELEVEN|HUGGING|^HF_|TOGETHER|FIREWORKS|DEEPSEEK|CLOUDFLARE|VERCEL|"
     r"NETLIFY|HEROKU|RAILWAY|DIGITALOCEAN|LINODE|STRIPE|PAYPAL|SQUARE|TWILIO|SENDGRID|MAILGUN|MAILCHIMP|"
     r"POSTMARK|RESEND|BILLING", "money"),
]
_KEY_RULES = [(re.compile(rx, re.I), rank) for rx, rank in KEY_RANK]


def worst(a, b):
    """The more urgent of two ranks; either may be None."""
    if a is None:
        return b
    if b is None:
        return a
    return a if ORDER[a] <= ORDER[b] else b


def for_pattern(name):
    """The rank a pattern implies, or None when the pattern is unknown here."""
    if name in NAME_RANK:
        return NAME_RANK[name]
    return GROUP_RANK.get(GROUPS.get(name))


def for_key(key):
    """The rank the name of a credential variable implies, or None."""
    for rx, rank in _KEY_RULES:
        if rx.search(key or ""):
            return rank
    return None


def rank(patterns=(), keys=()):
    """The worst rank anything known about a finding implies, defaulting to the narrowest.

    A value usually matches several patterns at once: the vendor's own format, and whatever shape the line
    around it had. Only the vendor patterns know what the key opens, so when one of them matched, the shapes
    are set aside — otherwise a Brave Search key written as `BRAVE_API_KEY=…` is ranked by the `=`."""
    named = [n for n in patterns if n in VENDORS]
    out = None
    for name in named or list(patterns):
        out = worst(out, for_pattern(name))
    for key in keys:
        out = worst(out, for_key(key))
    return out or DEFAULT
