"""One synthetic sample per credential pattern, generated at run time so no credential-shaped literal is committed.

Placeholders: {a:N} letters+digits, {U:N} upper+digits, {l:N} lower+digits, {h:N} lower hex, {b:N} base64
alphabet, {u:N} url-safe, {d:N} digits, {z:N} base32 lower, {g} lowercase UUID. Generated runs start and end
with a letter or digit so word boundaries behave as they would around real keys.
"""
import random
import re
import string

from afterprompt.vendor import PLACEHOLDER

CHARSETS = {
    "a": string.ascii_letters + string.digits,
    "U": string.ascii_uppercase + string.digits,
    "l": string.ascii_lowercase + string.digits,
    "h": "0123456789abcdef",
    "b": string.ascii_letters + string.digits + "+/",
    "u": string.ascii_letters + string.digits + "_-",
    "d": string.digits,
    "z": string.ascii_lowercase + "234567",
}

SAMPLES = {
    "anthropic_key": "sk-ant-api03-{u:95}",
    "openai_project_key": "sk-proj-{u:48}",
    "openai_legacy_key": "sk-{a:20}T3BlbkFJ{a:20}",
    "google_api_key": "AIza{u:35}",
    "groq_key": "gsk_{a:52}",
    "openrouter_key": "sk-or-v1-{h:64}",
    "huggingface_token": "hf_{a:34}",
    "replicate_token": "r8_{a:37}",
    "perplexity_key": "pplx-{a:48}",
    "elevenlabs_key": "sk_{h:48}",
    "xai_key": "xai-{a:80}",
    "deepgram_ctx": "DEEPGRAM_API_KEY={h:40}",
    "assemblyai_ctx": "ASSEMBLYAI_API_KEY={h:32}",
    "aws_access_key_id": "AKIA{U:16}",
    "aws_secret_key_ctx": "aws_secret_access_key = {b:40}",
    "aws_session_token_ctx": "aws_session_token = {b:120}",
    "azure_storage_key": "AccountKey={b:86}==",
    "azure_conn_string": "DefaultEndpointsProtocol=https;AccountName={l:12}",
    "azure_sas_signature": "https://acct.blob.core.windows.net/c?sv=2022-11-02&sig={b:44}%3D",
    "azure_ad_client_secret": "client_secret = {a:37}",
    "azure_openai_key_ctx": "AZURE_OPENAI_API_KEY={a:84}",
    "gcp_client_secret": "GOCSPX-{u:28}",
    "gcp_oauth_access_token": "ya29.{u:120}",
    "gcp_oauth_refresh_token": "1//0{u:80}",
    "google_oauth_auth_code": "4/0A{u:60}",
    "gcp_sa_private_key_id": "\"private_key_id\": \"{h:40}\"",
    "gcp_service_account_json": "\"type\": \"service_account\"",
    "google_session_cookie_ctx": "__Secure-1PSID={u:70}",
    "digitalocean_token": "dop_v1_{h:64}",
    "cloudflare_token_ctx": "CLOUDFLARE_API_TOKEN={a:40}",
    "vercel_token_ctx": "VERCEL_TOKEN={a:24}",
    "netlify_token_ctx": "NETLIFY_AUTH_TOKEN={u:43}",
    "flyio_token": "fo1_{u:43}",
    "terraform_cloud_token": "{a:14}.atlasv1.{u:70}",
    "heroku_key_ctx": "HEROKU_API_KEY={g}",
    "railway_token_ctx": "RAILWAY_TOKEN={g}",
    "supabase_service_key_ctx": "SUPABASE_SERVICE_ROLE_KEY=eyJ{u:20}.{u:40}.{u:30}",
    "supabase_secret_key": "sb_secret_{u:30}",
    "github_token": "ghp_{a:36}",
    "github_fine_grained_pat": "github_pat_{a:22}_{a:59}",
    "gitlab_token": "glpat-{u:20}",
    "bitbucket_ctx": "BITBUCKET_APP_PASSWORD={a:24}",
    "npm_token": "npm_{a:36}",
    "npmrc_auth_token": "//registry.npmjs.org/:_authToken={u:36}",
    "pypi_token": "pypi-AgEIcHlwaS5vcmc{u:70}",
    "rubygems_key": "rubygems_{h:48}",
    "dockerhub_pat": "dckr_pat_{u:27}",
    "jfrog_access_token": "AKCp{a:73}",
    "jfrog_reference_token": "cmVmdG9rZW46{b:40}",
    "jfrog_ctx": "ARTIFACTORY_API_KEY={a:64}",
    "slack_token": "xoxb-{d:12}-{d:12}-{a:24}",
    "slack_webhook": "https://hooks.slack.com/services/T{U:8}/B{U:8}/{a:24}",
    "discord_bot_token": "M{a:25}.{a:6}.{a:30}",
    "discord_webhook": "https://discord.com/api/webhooks/{d:18}/{u:68}",
    "telegram_bot_token": "{d:10}:AA{u:33}",
    "twilio_ctx": "TWILIO_AUTH_TOKEN={h:32}",
    "twilio_api_key_sid": "SK{h:32}",
    "sendgrid_key": "SG.{u:22}.{u:43}",
    "mailgun_key": "key-{h:32}",
    "mailchimp_key": "{h:32}-us6",
    "resend_key": "re_{a:8}_{a:24}",
    "postmark_ctx": "POSTMARK_SERVER_TOKEN={g}",
    "stripe_secret_key": "sk_live_{a:24}",
    "stripe_webhook_secret": "whsec_{a:32}",
    "square_token": "sq0atp-{u:22}",
    "shopify_token": "shpat_{h:32}",
    "airtable_key": "pat{a:14}.{h:64}",
    "asana_pat": "1/{d:16}:{h:32}",
    "atlassian_api_token": "ATATT3{u:180}",
    "atlassian_ctx": "JIRA_API_TOKEN={u:30}",
    "notion_token": "ntn_{a:46}",
    "linear_key": "lin_api_{a:40}",
    "figma_token": "figd_{u:40}",
    "sentry_dsn": "https://{h:32}@o{d:6}.ingest.sentry.io/{d:7}",
    "sentry_token": "sntrys_{a:60}",
    "datadog_ctx": "DD_API_KEY={h:32}",
    "newrelic_key": "NRAK-{U:27}",
    "posthog_key": "phc_{a:43}",
    "algolia_ctx": "ALGOLIA_ADMIN_KEY={h:32}",
    "brave_api_key_ctx": "BRAVE_API_KEY=BSA{u:28}",
    "brave_api_key": "BSA{a:28}",
    "mapbox_secret_token": "sk.eyJ{u:60}",
    "salesforce_session": "00D{a:15}!{a:90}",
    "salesforce_ctx": "SF_CLIENT_SECRET={a:20}",
    "linkedin_li_at_ctx": "li_at=AQED{u:130}",
    "linkedin_cookie_bare": "AQED{a:130}",
    "session_cookie_ctx": "sessionid={u:48}",
    "private_key_pem_body": "-----BEGIN RSA PRIVATE KEY-----\\n{b:64}",
    "private_key_header": "-----BEGIN OPENSSH PRIVATE KEY",
    "pgp_private_block": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "putty_private_key": "PuTTY-User-Key-File-3: ssh-ed25519",
    "age_secret_key": "AGE-SECRET-KEY-1{U:58}",
    "jwt": "eyJ{u:20}.eyJ{u:40}.{u:43}",
    "basic_auth_header": "Authorization: Basic {b:32}",
    "bearer_header": "Authorization: Bearer {u:40}",
    "curl_user_flag": "curl -u admin:{a:12} https://api.internal",
    "url_with_credentials": "postgres://appuser:{a:16}@db.{l:8}.com:5432/app",
    "prefixed_key": "api_{a:30}",
    "htpasswd_hash": "$2y$10${a:53}",
    "entra_client_secret": "{a:3}{d:1}Q~{a:34}",
    "azure_devops_pat": "{a:76}AZDO{a:4}",
    "azure_devops_pat_ctx": "AZURE_DEVOPS_PAT={z:52}",
    "azure_identifiable_key": "{a:52}JQQJ9{a:27}",
    "azure_identifiable_b64_44": "{a:33}AzCa{a:5}=",
    "azure_identifiable_b64_88": "{a:76}AzSe{a:5}A==",
    "azure_shared_access_key": "SharedAccessKey={b:44}=",
    "azure_conn_access_key": "Endpoint=sb://ns.servicebus.windows.net/;AccessKey={b:44}=",
    "azure_function_key_url": "https://{l:8}.azurewebsites.net/api/HttpTrigger?code={u:40}==",
    "conn_string_password": "Server=db;User Id=sa;Password={a:14};",
    "meta_access_token": "EAA{a:120}",
    "fcm_server_key": "AAAA{u:7}:APA91b{u:134}",
    "google_client_secret_json": "\"client_secret\": \"{u:35}\"",
    "google_chat_webhook": "https://chat.googleapis.com/v1/spaces/{u:11}/messages?key={u:39}&token={u:43}",
    "porkbun_api_key": "pk1_{h:64}",
    "registrar_dns_ctx": "NAMECHEAP_API_KEY={a:32}",
    "whatsapp_gateway_ctx": "WHATSAPP_TOKEN={u:40}",
    "il_payment_ctx": "TRANZILA_API_KEY={a:20}",
    "teams_webhook": "https://{l:8}.webhook.office.com/webhookb2/{g}@{g}/IncomingWebhook/{h:32}/{g}",
    "zapier_webhook": "https://hooks.zapier.com/hooks/catch/{d:7}/{l:6}",
    "make_webhook": "https://hook.eu1.make.com/{l:32}",
    "pkcs8_rsa_key_body": "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC{b:40}",
    "pkcs1_rsa_key_body": "MIIEpAIBAAKCAQEA{b:40}",
    "pkcs8_ec_key_body": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG{b:40}",
    "pkcs8_ed25519_key_body": "MC4CAQAwBQYDK2VwBCIEI{b:44}",
    "openssh_key_body": "b3BlbnNzaC1rZXktdjE{b:80}",
    "private_key_pem_multiline": "-----BEGIN PRIVATE KEY-----\n{b:64}",
    "http_header_key": "x-api-key: {a:32}",
    "bearer_literal": "\"Bearer {u:40}\"",
    "cookie_header": "Cookie: sid={u:40}",
    "curl_cookie_flag": "curl -b \"session={u:40}\" https://app.internal",
    "cli_secret_flag": "--password {a:14}",
    "sshpass_mysql_flag": "sshpass -p {a:12} ssh deploy@host",
    "url_secret_param": "https://api.service.io/v1/items?api_key={u:32}",
    "requests_basic_auth": "auth=(\"admin\", \"{a:14}\")",
    "user_password_pair": "username: admin password: {a:14}",
    "hebrew_password_prose": "הסיסמה היא {a:12}",
    "apps_script_deployment_id": "AKfycb{u:60}",
    "env_assignment": "DB_PASSWORD={a:20}",
    "generic_hex_secret": "signing_key = \"{h:64}\"",
    "password_in_prose": "the password is {a:14}",
}

_TOKEN = re.compile(r"\{([aUlhbudz]):(\d+)\}|\{g\}")


class SecretFactory:
    def __init__(self, seed=1234):
        self.r = random.Random(seed)

    def chars(self, kind, n):
        cs = CHARSETS[kind]
        edge = "".join(c for c in cs if c.isalnum())
        while True:
            if n == 1:
                s = self.r.choice(edge)
            else:
                s = self.r.choice(edge) + "".join(self.r.choice(cs) for _ in range(n - 2)) + self.r.choice(edge)
            if kind in ("a", "u", "b") and n >= 8 and not (any(c.isdigit() for c in s) and any(c.isupper() for c in s)
                                                            and any(c.islower() for c in s)):
                continue
            if not PLACEHOLDER.search(s.encode()):
                return s

    def uuid(self):
        h = self.chars("h", 32)
        return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"

    def render(self, template):
        def sub(m):
            if m.group(0) == "{g}":
                return self.uuid()
            return self.chars(m.group(1), int(m.group(2)))
        return _TOKEN.sub(sub, template)

    def sample(self, name):
        return self.render(SAMPLES[name])
