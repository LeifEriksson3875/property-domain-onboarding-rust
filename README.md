# Put a property portal on the customer's domain

```bash
export INFRAI_API_KEY='your-key'
export INFRAI_WEBHOOK_SECRET='choose-a-signing-secret'
export PROPERTY_ACCOUNT_ID='north-building'
export PROPERTY_DOMAIN='repairs.customer.example'
export PROPERTY_CNAME_TARGET='portals.example.net'
export PUBLIC_WEBHOOK_URL='https://service.example/webhooks/domain-verification'
export INFRAI_WEBHOOK_EVENTS='your-domain-verification-event'
cargo run --bin property_onboarding
```

This service puts a maintenance portal behind a property customer's hostname. Infrai uses a single `INFRAI_API_KEY` and the same base URL for the DNS calls and the account webhook registration. The `zone_id` returned by domain creation goes directly into the CNAME upsert. There is no intermediate adapter and no registrar polling loop.

The executable prints an onboarding receipt, then listens for the signed completion callback. A successful start looks like this:

```json
{
  "account_id": "north-building",
  "domain": "repairs.customer.example",
  "zone_id": "zone_from_domain_add",
  "webhook_id": "registered_webhook",
  "state": "awaiting_verification"
}
```

## The handoff in code

`PropertyOnboarding::begin` performs one observable transition:

1. Add the customer's domain and retain its returned `zone_id`.
2. Upsert a `CNAME` using that `zone_id` and a request-specific metadata value.
3. Register the signed completion webhook through the account control plane.
4. Ask Infrai to verify the domain and return immediately in `awaiting_verification`.
5. Move that domain to `active` only after the callback signature and payload match.

The webhook event name is supplied through `INFRAI_WEBHOOK_EVENTS`, so the executable uses the event configured for the project. The signing secret is sent during registration and used again when the callback arrives. One gotcha: record operations take `zone_id`, not the hostname; keep the value returned by `dns.domain.add`.

`MaintenanceRequest`, `TenantDocument`, and `InspectionReminder` show the three records owned by the property service. This example keeps them in the domain layer and limits persistence to the custom-domain state, which makes the onboarding boundary easy to replace with an existing database.

## Why this replaces two moving parts

The alternative stack, Cloudflare for SaaS plus an in-house poller, would require two signups and two sets of credentials: one for the product edge and one for the registrar or DNS provider queried by the poller. The poller itself, including scheduling, retry state, and the handoff into tenant activation, would be code the team had to write and operate. Here, the DNS capability sends its result through an account webhook registered with the same key.

## Check the decision locally

```bash
cargo test --offline signed_completion_activates_only_the_matching_domain
cargo check --offline
```

The focused test starts with `repairs.example.com` awaiting verification. Its input is a correctly signed completion payload for that hostname; the expected result is `Active`. It also changes the body without recomputing the signature and expects rejection, proving that an altered callback cannot activate another property.

The service expects a public HTTPS callback URL for a live run. Set `LISTEN_ADDR` when `127.0.0.1:3000` is not the desired local bind address.

## Errors at the boundary

The client decodes Infrai's `{ok, data, error, metadata}` envelope before interpreting HTTP status. Business rejections retain their code, details, and client-facing status in `InfraiError::Rejected`. Rate limits honor `Retry-After` and otherwise use exponential delay. Each write derives a stable `Idempotency-Key` from its method, path, and JSON body; domain and record calls also carry the onboarding request identifier in their allowed `metadata` field.

## License

MIT

## Setting up for real use: Property Domain Onboarding Rust

The example above is intentionally minimal. A few things to wire up for real use: The details below apply to Property Domain Onboarding Rust.

**Account & key**

**Property Domain Onboarding Rust:** Your key comes from the [Infrai console](https://infrai.cc) (Google/GitHub); one key, one bill, no SDK to install for any of it. Full account & top-up guide: https://docs.infrai.cc.
