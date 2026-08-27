# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |

## Scope

This repository contains the provider-neutral `@huggingbay/coprocessor` SDK
and bounded Grok/Cursor connector examples. It does not contain Bay Run
service infrastructure, deployment configuration, credentials, provider
account state, or customer data.

The SDK fails closed by default when the coprocessor response is unavailable
or does not satisfy its signed contract. Its receipt and decision-evidence
checks attest to declared binding and server metadata; they do not prove
execution, answer truth, model quality, or universal safety. Guard is limited
to its published English prompt-injection scope, and Rerank is an ordering
signal rather than a correctness verdict.

## Reporting a vulnerability

Please report vulnerabilities privately through [GitHub Security Advisories](https://github.com/barneywohl/huggingbay-coprocessor/security/advisories/new).
If the repository is not yet public, do not disclose sensitive details in a
public issue; contact the maintainer through an established private channel and
wait for acknowledgement.

Include the affected version, a minimal reproduction, impact, and any
suggested mitigation. Do not include API tokens, private keys, personal data,
customer content, or other live secrets in a report.

Connector examples use placeholders and the provider's supported
authentication flow. Never commit a bearer, API key, private key, or provider
credential to this repository.
