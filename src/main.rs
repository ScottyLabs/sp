use std::{collections::HashMap, sync::Arc};

use axum::{
    Form, Router,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose};
use samael::{
    metadata::EntityDescriptor,
    service_provider::{ServiceProvider, ServiceProviderBuilder},
    traits::ToXml,
};
use tokio::net::TcpListener;

#[derive(Clone)]
struct AppState {
    sp: Arc<ServiceProvider>,
    metadata: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();

    // Probe for SSL certificate files and directories
    let probe_result = openssl_probe::probe();
    let cert_file = probe_result
        .cert_file
        .expect("Failed to find SSL cert file");
    let cert_dir = probe_result.cert_dir.expect("Failed to find SSL cert dir");

    unsafe {
        // set_var is safe to call in a single-threaded program
        std::env::set_var("SSL_CERT_FILE", cert_file);
        std::env::set_var("SSL_CERT_DIR", cert_dir);
    }

    let resp = reqwest::get("https://login.cmu.edu/idp/shibboleth")
        .await
        .map_err(|e| format!("Failed to fetch IdP metadata: {e}"))?
        .text()
        .await?;
    let idp_metadata: EntityDescriptor = samael::metadata::de::from_str(&resp)?;

    // Read keys from base64 environment variables
    let private_key_pem = general_purpose::STANDARD.decode(dotenvy::var("PRIVATE_KEY_BASE64")?)?;
    let public_key_pem = general_purpose::STANDARD.decode(dotenvy::var("PUBLIC_KEY_BASE64")?)?;

    let pub_key = openssl::x509::X509::from_pem(&public_key_pem)?;
    let private_key = openssl::rsa::Rsa::private_key_from_pem_passphrase(
        &private_key_pem,
        dotenvy::var("PASSPHRASE")?.as_bytes(),
    )?;

    // Convert RSA key to generic PKey
    let private_key = openssl::pkey::PKey::from_rsa(private_key)?;

    let base_url = dotenvy::var("BASE_URL")?;
    let sp = ServiceProviderBuilder::default()
        .entity_id(format!("{base_url}/saml"))
        .key(private_key)
        .certificate(pub_key)
        .allow_idp_initiated(true)
        .idp_metadata(idp_metadata)
        .acs_url(format!("{base_url}/saml/acs"))
        .slo_url(format!("{base_url}/saml/slo"))
        .build()?;

    let metadata = sp.metadata()?.to_string()?;
    let state = AppState {
        sp: Arc::new(sp),
        metadata,
    };

    let app = Router::new()
        .route("/saml/metadata", get(metadata_handler))
        .route("/saml/acs", post(acs_handler))
        .route("/health", get(|| async { "OK" }))
        .with_state(state);

    let listener = TcpListener::bind("0.0.0.0:8080").await?;

    println!("Service Provider running on {base_url}");
    println!("Metadata available at: {base_url}/saml/metadata");

    axum::serve(listener, app).await?;
    Ok(())
}

async fn metadata_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert(
        "content-type",
        "application/samlmetadata+xml".parse().unwrap(),
    );

    (headers, state.metadata)
}

async fn acs_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    Form(form_data): Form<HashMap<String, String>>,
) -> Result<String, StatusCode> {
    if let Some(encoded_resp) = form_data.get("SAMLResponse") {
        // Decode the base64-encoded SAML response
        match state.sp.parse_base64_response(encoded_resp, None) {
            Ok(response) => Ok(format!("{response:?}")),
            Err(e) => {
                eprintln!("Error parsing SAML response: {e:?}");
                Err(StatusCode::BAD_REQUEST)
            }
        }
    } else {
        Err(StatusCode::BAD_REQUEST)
    }
}
