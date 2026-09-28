use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use property_domain_onboarding::{
    infrai::{InfraiClient, InfraiError},
    property_onboarding::{OnboardingError, PropertyOnboarding, PropertyPortfolio},
};
use serde::Serialize;
use std::{env, net::SocketAddr};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
enum ServiceError {
    #[error("missing environment variable {0}")]
    MissingEnv(&'static str),
    #[error("invalid environment variable {0}")]
    InvalidEnv(&'static str),
    #[error(transparent)]
    Onboarding(#[from] OnboardingError),
    #[error("server failed: {0}")]
    Server(#[from] std::io::Error),
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

#[tokio::main]
async fn main() -> Result<(), ServiceError> {
    let api_key = required("INFRAI_API_KEY")?;
    let webhook_secret = required("INFRAI_WEBHOOK_SECRET")?;
    let domain = required("PROPERTY_DOMAIN")?;
    let account_id = required("PROPERTY_ACCOUNT_ID")?;
    let cname_target = required("PROPERTY_CNAME_TARGET")?;
    let webhook_url = required("PUBLIC_WEBHOOK_URL")?;
    let webhook_events = required("INFRAI_WEBHOOK_EVENTS")?
        .split(',')
        .map(str::trim)
        .filter(|event| !event.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if webhook_events.is_empty() {
        return Err(ServiceError::InvalidEnv("INFRAI_WEBHOOK_EVENTS"));
    }

    // A single INFRAI_API_KEY authorizes both DNS onboarding and account webhook setup.
    let onboarding = PropertyOnboarding::new(InfraiClient::new(api_key), webhook_secret);
    let receipt = onboarding
        .begin(
            &PropertyPortfolio {
                account_id,
                domain,
                cname_target,
                webhook_url,
                webhook_events,
            },
            &Uuid::new_v4().to_string(),
        )
        .await?;
    println!("{}", serde_json::to_string_pretty(&receipt).unwrap());

    let address: SocketAddr = env::var("LISTEN_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:3000".to_owned())
        .parse()
        .map_err(|_| ServiceError::InvalidEnv("LISTEN_ADDR"))?;
    let app = Router::new()
        .route("/webhooks/domain-verification", post(domain_webhook))
        .with_state(onboarding);
    let listener = tokio::net::TcpListener::bind(address).await?;
    println!("listening on http://{address}/webhooks/domain-verification");
    axum::serve(listener, app).await?;
    Ok(())
}

fn required(name: &'static str) -> Result<String, ServiceError> {
    env::var(name).map_err(|_| ServiceError::MissingEnv(name))
}

async fn domain_webhook(
    State(onboarding): State<PropertyOnboarding>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let signature = headers
        .get("x-infrai-signature")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    match onboarding.accept_verification(signature, &body).await {
        Ok(state) => (StatusCode::OK, Json(serde_json::json!({ "state": state }))),
        Err(error) => {
            let status = match &error {
                OnboardingError::InvalidSignature | OnboardingError::InvalidPayload(_) => {
                    StatusCode::BAD_REQUEST
                }
                OnboardingError::Infrai(InfraiError::Rejected { status, .. }) => {
                    StatusCode::from_u16(*status).unwrap_or(StatusCode::BAD_REQUEST)
                }
                OnboardingError::Infrai(_) => StatusCode::BAD_GATEWAY,
            };
            (
                status,
                Json(serde_json::json!(ErrorBody {
                    error: error.to_string()
                })),
            )
        }
    }
}
