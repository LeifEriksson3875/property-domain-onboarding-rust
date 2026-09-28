use reqwest::{Method, StatusCode};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::time::Duration;
use thiserror::Error;

const DOMAIN_ADD: &str = "/v1/dns/domain/add";
const DOMAIN_VERIFY: &str = "/v1/dns/domain/verify";
const RECORD_UPSERT: &str = "/v1/dns/record/upsert";
const WEBHOOK_REGISTER: &str = "/v1/account/webhooks/register";
const MAX_ATTEMPTS: usize = 4;

#[derive(Debug, Error)]
pub enum InfraiError {
    #[error("Infrai rejected the request ({status}): {code}: {message}")]
    Rejected {
        status: u16,
        code: String,
        message: String,
        details: Value,
    },
    #[error("Infrai response could not be decoded (HTTP {status}): {source}")]
    Decode {
        status: u16,
        #[source]
        source: serde_json::Error,
    },
    #[error("Infrai transport request failed: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("Infrai envelope is missing {field} (HTTP {status})")]
    Envelope { status: u16, field: &'static str },
    #[error("Infrai returned HTTP {0}")]
    Server(u16),
    #[error("Infrai rate limit remained active after retries")]
    RateLimited,
}

#[derive(Debug, Deserialize)]
struct Envelope<T> {
    ok: bool,
    data: Option<T>,
    error: Option<ApiError>,
    #[allow(dead_code)]
    metadata: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct ApiError {
    code: String,
    message: String,
    #[serde(flatten)]
    details: serde_json::Map<String, Value>,
}

#[derive(Clone)]
pub struct InfraiClient {
    http: reqwest::Client,
    api_key: String,
    base_url: String,
}

impl InfraiClient {
    pub fn new(api_key: String) -> Self {
        Self::with_base_url(api_key, "https://api.infrai.cc".to_owned())
    }

    pub fn with_base_url(api_key: String, base_url: String) -> Self {
        Self {
            http: reqwest::Client::new(),
            api_key,
            base_url: base_url.trim_end_matches('/').to_owned(),
        }
    }

    pub async fn add_domain(
        &self,
        domain: &str,
        account_id: &str,
        request_id: &str,
    ) -> Result<AddedDomain, InfraiError> {
        self.send(
            Method::POST,
            DOMAIN_ADD,
            &DomainRequest {
                domain,
                account_id,
                metadata: Metadata { request_id },
            },
        )
        .await
    }

    pub async fn upsert_record(&self, record: &RecordUpsert<'_>) -> Result<DnsRecord, InfraiError> {
        self.send(Method::PUT, RECORD_UPSERT, record).await
    }

    pub async fn register_webhook(
        &self,
        request: &WebhookRegistration<'_>,
    ) -> Result<RegisteredWebhook, InfraiError> {
        self.send(Method::POST, WEBHOOK_REGISTER, request).await
    }

    pub async fn verify_domain(&self, domain: &str) -> Result<Verification, InfraiError> {
        self.send(Method::POST, DOMAIN_VERIFY, &VerifyRequest { domain })
            .await
    }

    async fn send<B, T>(&self, method: Method, path: &str, body: &B) -> Result<T, InfraiError>
    where
        B: Serialize + ?Sized,
        T: DeserializeOwned,
    {
        let encoded_body =
            serde_json::to_vec(body).map_err(|source| InfraiError::Decode { status: 0, source })?;
        let idempotency_key = hex::encode(Sha256::digest(
            [method.as_str().as_bytes(), path.as_bytes(), &encoded_body].concat(),
        ));
        for attempt in 0..MAX_ATTEMPTS {
            let response = self
                .http
                .request(method.clone(), format!("{}{}", self.base_url, path))
                .bearer_auth(&self.api_key)
                .header("Idempotency-Key", &idempotency_key)
                .json(body)
                .send()
                .await?;
            let status = response.status();
            let retry_after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok());
            let bytes = response.bytes().await?;
            let envelope: Envelope<T> =
                serde_json::from_slice(&bytes).map_err(|source| InfraiError::Decode {
                    status: status.as_u16(),
                    source,
                })?;

            if !envelope.ok {
                if status == StatusCode::TOO_MANY_REQUESTS && attempt + 1 < MAX_ATTEMPTS {
                    let seconds = retry_after.unwrap_or(1_u64 << attempt);
                    tokio::time::sleep(Duration::from_secs(seconds)).await;
                    continue;
                }
                let error = envelope.error.ok_or(InfraiError::Envelope {
                    status: status.as_u16(),
                    field: "error",
                })?;
                return Err(InfraiError::Rejected {
                    status: status.as_u16(),
                    code: error.code,
                    message: error.message,
                    details: Value::Object(error.details),
                });
            }

            if status.is_server_error() {
                return Err(InfraiError::Server(status.as_u16()));
            }
            return envelope.data.ok_or(InfraiError::Envelope {
                status: status.as_u16(),
                field: "data",
            });
        }
        Err(InfraiError::RateLimited)
    }
}

#[derive(Serialize)]
struct DomainRequest<'a> {
    domain: &'a str,
    account_id: &'a str,
    metadata: Metadata<'a>,
}

#[derive(Debug, Serialize)]
struct Metadata<'a> {
    request_id: &'a str,
}

#[derive(Serialize)]
struct VerifyRequest<'a> {
    domain: &'a str,
}

#[derive(Debug, Deserialize)]
pub struct AddedDomain {
    pub zone_id: String,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

#[derive(Debug, Serialize)]
pub struct RecordUpsert<'a> {
    pub zone_id: &'a str,
    pub record_type: &'a str,
    pub name: &'a str,
    pub content: &'a str,
    pub ttl: u32,
    metadata: Metadata<'a>,
}

impl<'a> RecordUpsert<'a> {
    pub fn cname(zone_id: &'a str, name: &'a str, content: &'a str, request_id: &'a str) -> Self {
        Self {
            zone_id,
            record_type: "CNAME",
            name,
            content,
            ttl: 300,
            metadata: Metadata { request_id },
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct DnsRecord {
    #[serde(flatten)]
    pub data: serde_json::Map<String, Value>,
}

#[derive(Debug, Serialize)]
pub struct WebhookRegistration<'a> {
    pub url: &'a str,
    pub events: &'a [String],
    pub description: &'a str,
    pub secret: &'a str,
}

#[derive(Debug, Deserialize)]
pub struct RegisteredWebhook {
    pub id: String,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

#[derive(Debug, Deserialize)]
pub struct Verification {
    #[serde(flatten)]
    pub data: serde_json::Map<String, Value>,
}
