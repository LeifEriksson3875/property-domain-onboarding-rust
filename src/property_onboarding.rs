use crate::infrai::{
    InfraiClient, InfraiError, RecordUpsert, RegisteredWebhook, Verification, WebhookRegistration,
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{collections::HashMap, sync::Arc};
use thiserror::Error;
use tokio::sync::RwLock;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug, Deserialize)]
pub struct PropertyPortfolio {
    pub account_id: String,
    pub domain: String,
    pub cname_target: String,
    pub webhook_url: String,
    pub webhook_events: Vec<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DomainState {
    AwaitingVerification,
    Active,
}

#[derive(Clone, Debug, Serialize)]
pub struct OnboardingReceipt {
    pub account_id: String,
    pub domain: String,
    pub zone_id: String,
    pub webhook_id: String,
    pub state: DomainState,
}

#[derive(Clone, Debug, Serialize)]
pub struct MaintenanceRequest {
    pub property_id: String,
    pub summary: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct TenantDocument {
    pub tenant_id: String,
    pub document_name: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct InspectionReminder {
    pub property_id: String,
    pub due_on: String,
}

#[derive(Clone)]
pub struct PropertyOnboarding {
    infrai: InfraiClient,
    webhook_secret: Arc<String>,
    domains: Arc<RwLock<HashMap<String, DomainState>>>,
}

#[derive(Debug, Error)]
pub enum OnboardingError {
    #[error(transparent)]
    Infrai(#[from] InfraiError),
    #[error("webhook signature is invalid")]
    InvalidSignature,
    #[error("webhook payload is invalid: {0}")]
    InvalidPayload(#[from] serde_json::Error),
}

#[derive(Debug, Deserialize)]
struct DomainEvent {
    domain: String,
    verified: bool,
}

impl PropertyOnboarding {
    pub fn new(infrai: InfraiClient, webhook_secret: String) -> Self {
        Self {
            infrai,
            webhook_secret: Arc::new(webhook_secret),
            domains: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn begin(
        &self,
        portfolio: &PropertyPortfolio,
        request_id: &str,
    ) -> Result<OnboardingReceipt, OnboardingError> {
        let domain = self
            .infrai
            .add_domain(&portfolio.domain, &portfolio.account_id, request_id)
            .await?;

        let record_request_id = format!("{request_id}:cname");
        self.infrai
            .upsert_record(&RecordUpsert::cname(
                &domain.zone_id,
                &portfolio.domain,
                &portfolio.cname_target,
                &record_request_id,
            ))
            .await?;

        let webhook: RegisteredWebhook = self
            .infrai
            .register_webhook(&WebhookRegistration {
                url: &portfolio.webhook_url,
                events: &portfolio.webhook_events,
                description: "Property domain verification completion",
                secret: &self.webhook_secret,
            })
            .await?;

        let _verification: Verification = self.infrai.verify_domain(&portfolio.domain).await?;
        self.domains
            .write()
            .await
            .insert(portfolio.domain.clone(), DomainState::AwaitingVerification);

        Ok(OnboardingReceipt {
            account_id: portfolio.account_id.clone(),
            domain: portfolio.domain.clone(),
            zone_id: domain.zone_id,
            webhook_id: webhook.id,
            state: DomainState::AwaitingVerification,
        })
    }

    pub async fn accept_verification(
        &self,
        signature_hex: &str,
        body: &[u8],
    ) -> Result<Option<DomainState>, OnboardingError> {
        let signature =
            hex::decode(signature_hex).map_err(|_| OnboardingError::InvalidSignature)?;
        let mut mac = HmacSha256::new_from_slice(self.webhook_secret.as_bytes())
            .map_err(|_| OnboardingError::InvalidSignature)?;
        mac.update(body);
        mac.verify_slice(&signature)
            .map_err(|_| OnboardingError::InvalidSignature)?;

        let event: DomainEvent = serde_json::from_slice(body)?;
        let mut domains = self.domains.write().await;
        let Some(state) = domains.get_mut(&event.domain) else {
            return Ok(None);
        };
        if event.verified {
            *state = DomainState::Active;
        }
        Ok(Some(state.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn signed_completion_activates_only_the_matching_domain() {
        let service = PropertyOnboarding::new(
            InfraiClient::with_base_url(String::new(), "http://127.0.0.1".to_owned()),
            "local-webhook-secret".to_owned(),
        );
        service.domains.write().await.insert(
            "repairs.example.com".to_owned(),
            DomainState::AwaitingVerification,
        );
        let body = br#"{"domain":"repairs.example.com","verified":true}"#;
        let mut mac = HmacSha256::new_from_slice(b"local-webhook-secret").unwrap();
        mac.update(body);
        let signature = hex::encode(mac.finalize().into_bytes());

        let state = service.accept_verification(&signature, body).await.unwrap();

        assert_eq!(state, Some(DomainState::Active));

        let other_body = br#"{"domain":"other.example.com","verified":true}"#;
        let mut other_mac = HmacSha256::new_from_slice(b"local-webhook-secret").unwrap();
        other_mac.update(other_body);
        let other_signature = hex::encode(other_mac.finalize().into_bytes());
        assert_eq!(
            service
                .accept_verification(&other_signature, other_body)
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            service
                .accept_verification(&signature, other_body)
                .await
                .unwrap_err()
                .to_string(),
            "webhook signature is invalid"
        );
    }
}
