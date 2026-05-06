<p align="center">
  <a href="https://github.com/aisecuritygateway/aisecuritygateway">
    <img alt="AI Security Gateway" src="https://aisecuritygateway.ai/og.png" width="600" />
  </a>
</p>

<h3 align="center">The Open-Source AI Firewall & LLM Proxy</h3>

<p align="center">
  Stop sensitive data from leaking into LLM prompts. Drop-in OpenAI SDK compatible.<br />
  PII redaction · Secret detection · Prompt injection blocking · Self-hosted via Docker · Apache 2.0
</p>

<p align="center">
  <a href="https://github.com/aisecuritygateway/aisecuritygateway"><strong>Get Started</strong></a> ·
  <a href="https://aisecuritygateway.ai/docs"><strong>Docs</strong></a> ·
  <a href="https://aisecuritygateway.ai/open-source"><strong>OSS vs Cloud</strong></a> ·
  <a href="https://aisecuritygateway.ai"><strong>Managed Cloud (1M free credits)</strong></a>
</p>

<p align="center">
  <a href="https://github.com/aisecuritygateway/aisecuritygateway/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue?style=for-the-badge" alt="Apache 2.0" /></a>&nbsp;
  <a href="https://github.com/aisecuritygateway/aisecuritygateway"><img src="https://img.shields.io/badge/Docker-Quickstart-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker" /></a>&nbsp;
  <a href="https://aisecuritygateway.ai/docs/openai-compatible-proxy"><img src="https://img.shields.io/badge/OpenAI_SDK-Compatible-10a37f?style=for-the-badge&logo=openai&logoColor=white" alt="OpenAI Compatible" /></a>
</p>

---

## How It Works

```
                           ┌─────────────────────────────┐
                           │        AISG Gateway          │
    ┌──────────┐           │                              │           ┌──────────────┐
    │          │  POST     │  1. Auth (API key)           │           │              │
    │ Your App ├──────────▸│  2. Resolve provider/model   │──────────▸│ LLM Provider │
    │          │           │  3. DLP scan (Presidio)      │           │ (Groq/OpenAI)│
    │          │◂──────────│  4. Block or redact           │◂──────────│              │
    └──────────┘  response │  5. Forward to upstream      │  response └──────────────┘
                           │  6. Return with metadata     │
                           │                              │
                           │         ┌──────────┐         │
                           │         │ Presidio │         │
                           │         │ (PII/NER)│         │
                           │         └──────────┘         │
                           └─────────────────────────────┘
```

AISG is an **OpenAI-compatible proxy** that acts as an AI firewall. It sits between your app and LLM providers, scanning every request for PII, secrets, and prompt injection attacks before anything reaches the model.

### Key Features

- **PII Redaction** — emails, phone numbers, credit cards, SSNs, names, locations, IP addresses
- **Secret Detection** — API keys, AWS credentials, GitHub tokens, private keys, Slack webhooks
- **Prompt Injection Blocking** — detects jailbreak and instruction override attempts
- **OpenAI SDK Compatible** — drop-in replacement, change one line of code
- **Multi-Provider Routing** — BYOK, swap providers in config
- **Fail-Closed Security** — if the safety layer is down, requests are **blocked**, never forwarded unscanned
- **Zero Cloud Dependencies** — runs entirely on your machine via Docker
- **No Telemetry** — zero external calls, no analytics, no phone-home

---

## Quickstart (60 seconds)

```bash
git clone https://github.com/aisecuritygateway/aisecuritygateway.git
cd aisecuritygateway
cp .env.example .env        # add your provider key
docker compose up --build   # gateway + presidio
```

```bash
curl http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer change-me-to-a-real-secret" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "llama-3.3-70b-versatile",
    "messages": [{"role": "user", "content": "My email is alice@acme.com and SSN is 123-45-6789"}]
  }'
```

The gateway redacts the email and SSN before forwarding. The response includes `aisg_metadata.pii_detected: true`.

---

## What Gets Detected

| PII (Presidio built-ins) | Developer Secrets (custom) | Prompt Injection |
|---|---|---|
| `EMAIL_ADDRESS` | `API_KEY` (OpenAI, Anthropic, GCP) | Ignore previous instructions |
| `PHONE_NUMBER` | `AWS_ACCESS_KEY` | Disregard your rules |
| `CREDIT_CARD` | `PRIVATE_KEY` (RSA, EC, etc.) | System prompt extraction |
| `US_SSN` | `GITHUB_TOKEN` (PAT, OAuth) | DAN / jailbreak attempts |
| `PERSON`, `LOCATION` | `SLACK_WEBHOOK` | Developer mode exploits |
| `IP_ADDRESS` | | |

**13 entity types** out of the box — the [managed cloud](https://aisecuritygateway.ai) extends this to **28+** with OCR image scanning.

---

## Security Model

- **Fail-closed by default** — if Presidio is unreachable, requests are **blocked**, never forwarded unscanned
- **Auth by default** — API key authentication enabled out of the box
- **No telemetry** — zero external calls, no analytics, no phone-home
- **Secret scrubbing** — structured logs automatically mask API keys and tokens
- **Rate limiting** — token bucket per API key (default 10 req/sec)

---

## OSS vs Managed Cloud

This repo gives you the core AI security proxy. The managed [AI Security Gateway Cloud](https://aisecuritygateway.ai) adds everything you need to run it across teams at scale.

| | OSS (this repo) | [Cloud](https://aisecuritygateway.ai) |
|---|:---:|:---:|
| PII detection & redaction (text) | 13 entity types | 28+ entity types |
| OCR image scanning | — | Yes |
| Secret leak prevention | 5 recognizers | Extended (incl. AWS Secret Key, crypto, MAC) |
| Prompt injection blocking | 5 core patterns | Extended pattern library |
| Routing | Header-based (`x-provider`) | Smart Router + real-time pricing |
| Failover | — | Automatic intelligent chains |
| Cost optimization | — | Automatic (cheapest per request) |
| Budget enforcement | — | Per-project caps + alerts + analytics |
| Self-hosted | Yes | Managed |
| Multi-project management | — | Yes |
| Project-level DLP policies | — | Yes |
| Dashboards, leak reports & analytics | — | Yes |
| Real-time model pricing registry | — | Yes |
| Managed provider keys (no BYOK required) | — | Yes |
| SLA & support | Community | Yes |

> **Skip the setup?** [aisecuritygateway.ai](https://aisecuritygateway.ai) — everything here plus dashboards, smart cost routing, and 8+ providers. 1M free credits, no credit card.

---

<p align="center">
  <a href="https://theresanaiforthat.com/ai/aisecuritygateway/?ref=featured&v=7352275" rel="nofollow noopener noreferrer">
    <img width="200" src="https://media.theresanaiforthat.com/featured-on-taaft.png?width=600" alt="Featured on There's An AI For That" />
  </a>
</p>

---

<p align="center">
  <a href="https://github.com/aisecuritygateway/aisecuritygateway"><strong>⭐ Star the repo</strong></a> ·
  <a href="https://aisecuritygateway.ai/open-source"><strong>Learn more</strong></a> ·
  <a href="https://aisecuritygateway.ai"><strong>Try the managed cloud free</strong></a>
</p>

<p align="center">
  <sub>
    <a href="https://aisecuritygateway.ai/security">Security</a> ·
    <a href="https://github.com/aisecuritygateway/aisecuritygateway/blob/main/LICENSE">License (Apache 2.0)</a> ·
    <a href="https://linkedin.com/company/ai-security-gateway">LinkedIn</a> ·
    <a href="https://x.com/AISGateway">X / Twitter</a> ·
    <a href="https://www.youtube.com/@AISecurityGateway">YouTube</a>
  </sub>
</p>

<p align="center">
  <sub>Built by <a href="https://aisecuritygateway.ai">Datum Fuse LLC</a> — making AI safe by default.</sub>
</p>
