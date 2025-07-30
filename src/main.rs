use std::{collections::HashMap, sync::Arc};

use axum::{
    Form, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose};
use chrono::{Duration, Utc};
use jsonwebtoken::{EncodingKey, Header, encode};
use samael::{
    metadata::EntityDescriptor,
    service_provider::{ServiceProvider, ServiceProviderBuilder},
    traits::ToXml,
};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

#[derive(Clone)]
struct AppState {
    sp: Arc<ServiceProvider>,
    idp_metadata: Arc<EntityDescriptor>,
    metadata: String,
    jwt_secret: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    email: String,
    name: String,
    exp: i64,
    iat: i64,
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
        .idp_metadata(idp_metadata.clone())
        .acs_url(format!("{base_url}/saml/acs"))
        .slo_url(format!("{base_url}/saml/slo"))
        .build()?;

    let metadata = sp.metadata()?.to_string()?;
    let state = AppState {
        sp: Arc::new(sp),
        idp_metadata: Arc::new(idp_metadata),
        metadata,
        jwt_secret: dotenvy::var("JWT_SECRET")?,
    };

    let app = Router::new()
        .route("/", get(home_handler))
        .route("/login", get(login_handler))
        .route("/saml/metadata", get(metadata_handler))
        .route("/saml/acs", post(acs_handler))
        .route("/health", get(|| async { "OK" }))
        .with_state(state);

    let listener = TcpListener::bind("0.0.0.0:8080").await?;

    println!("Service Provider running on {base_url}");
    println!("Login at: {base_url}/login");
    println!("Metadata available at: {base_url}/saml/metadata");

    axum::serve(listener, app).await?;
    Ok(())
}

async fn login_handler(State(state): State<AppState>) -> Result<impl IntoResponse, StatusCode> {
    // Extract the SSO URL from IdP metadata
    let cmu_idp_url = get_idp_sso_url(&state.idp_metadata).ok_or_else(|| {
        eprintln!("Could not find SAML 2.0 HTTP-POST SSO endpoint in IdP metadata");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    println!("Using IdP SSO URL from metadata: {cmu_idp_url}");

    // Create a proper SAML authentication request using samael
    match state.sp.make_authentication_request(&cmu_idp_url) {
        Ok(authn_request) => {
            println!("Generated SAML request ID: {}", authn_request.id);

            // Convert the AuthnRequest to XML and base64 encode it
            let authn_request_xml = authn_request.to_string().map_err(|e| {
                eprintln!("Error serializing AuthnRequest to XML: {e:?}");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            let encoded_request = general_purpose::STANDARD.encode(authn_request_xml.as_bytes());

            // Create HTML form that auto-submits to CMU's IdP
            let html = format!(
                r#"
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Redirecting to CMU...</title>
                </head>
                <body>
                    <h2>Redirecting to CMU...</h2>
                    <p>If you are not redirected automatically, <button onclick="document.getElementById('saml').submit();">click here</button></p>

                    <form method="POST" action="{}" id="saml">
                        <input type="hidden" name="SAMLRequest" value="{}" />
                        <input type="hidden" name="RelayState" value="{}" />
                    </form>
                    
                    <script>
                        document.getElementById("saml").submit();
                    </script>
                </body>
                </html>
            "#,
                cmu_idp_url, encoded_request, authn_request.id
            );

            Ok(Html(html))
        }
        Err(e) => {
            eprintln!("Error creating SAML authentication request: {e:?}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

fn get_idp_sso_url(idp_metadata: &EntityDescriptor) -> Option<String> {
    idp_metadata
        .idp_sso_descriptors
        .as_ref()? // Get IdP SSO descriptors
        .iter()
        .flat_map(|descriptor| &descriptor.single_sign_on_services) // Get all SSO services
        .find(|service| service.binding == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST") // Find the HTTP-POST binding
        .map(|service| service.location.clone()) // Return the location URL
}

async fn home_handler(State(_): State<AppState>) -> Html<String> {
    let base_url = dotenvy::var("BASE_URL").unwrap_or_else(|_| "http://localhost:8080".to_string());

    Html(format!(
        r#"
        <!DOCTYPE html>
        <html>
        <head>
            <title>ScottyLabs SSO</title>
        </head>
        <body>
            <h1>ScottyLabs SSO</h1>
            <a href="{base_url}/login" class="button">Sign in with CMU</a>
            <p><small><a href="{base_url}/saml/metadata">Download SAML Metadata</a></small></p>
        </body>
        </html>
    "#
    ))
}

async fn metadata_handler(State(state): State<AppState>) -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert(
        "content-type",
        "application/samlmetadata+xml".parse().unwrap(),
    );

    (headers, state.metadata)
}

async fn acs_handler(
    State(state): State<AppState>,
    Form(form_data): Form<HashMap<String, String>>,
) -> Result<String, StatusCode> {
    if let Some(encoded_resp) = form_data.get("SAMLResponse") {
        // Extract RelayState which contains original request ID
        let expected_request_id = form_data.get("RelayState");

        if expected_request_id.is_none() {
            eprintln!("Missing RelayState in SAML response");
            return Err(StatusCode::BAD_REQUEST);
        }

        // Validate the SAML response against request ID
        let request_ids = expected_request_id.map(|id| vec![id.as_str()]);

        // Decode the base64-encoded SAML response
        match state
            .sp
            .parse_base64_response(encoded_resp, request_ids.as_deref())
        {
            Ok(response) => {
                println!("SAML Response received: {response:?}");

                // Extract user information from SAML response
                let email = extract_saml_attribute(&response, "eduPersonPrincipalName")
                    .ok_or_else(|| {
                        eprintln!("Missing eduPersonPrincipalName attribute in SAML response");
                        StatusCode::BAD_REQUEST
                    })?;

                let name = extract_saml_attribute(&response, "displayName").ok_or_else(|| {
                    eprintln!("Missing displayName attribute in SAML response");
                    StatusCode::BAD_REQUEST
                })?;

                // Create JWT claims
                let now = Utc::now();
                let claims = Claims {
                    sub: email.clone(),
                    email,
                    name,
                    exp: (now + Duration::hours(24)).timestamp(),
                    iat: now.timestamp(),
                };

                // Sign JWT
                match encode(
                    &Header::default(),
                    &claims,
                    &EncodingKey::from_secret(state.jwt_secret.as_ref()),
                ) {
                    Ok(token) => {
                        // Return success page with JWT
                        let html = format!(
                            r#"
                            <!DOCTYPE html>
                            <html>
                            <head>
                                <title>Login Successful</title>
                            </head>
                            <body>
                                <h2>Login Successful</h2>
                                <p>Welcome, <strong>{}</strong></p>
                                <p>Your JWT token: {token}</p>
                                <p><small>This token is valid for 24 hours.</small></p>
                            </body>
                            </html>
                        "#,
                            claims.name
                        );

                        Ok(html)
                    }
                    Err(e) => {
                        eprintln!("JWT encoding error: {e:?}");
                        Err(StatusCode::INTERNAL_SERVER_ERROR)
                    }
                }
            }
            Err(e) => {
                eprintln!("Error parsing SAML response: {e:?}");
                Err(StatusCode::BAD_REQUEST)
            }
        }
    } else {
        Err(StatusCode::BAD_REQUEST)
    }
}

fn extract_saml_attribute(
    assertion: &samael::schema::Assertion,
    attr_name: &str,
) -> Option<String> {
    assertion
        .attribute_statements
        .as_ref()?
        .iter()
        .flat_map(|stmt| stmt.attributes.iter())
        .find(|attr| attr.name.as_deref() == Some(attr_name))
        .and_then(|attr| attr.values.first())
        .and_then(|value| value.value.as_ref())
        .map(|s| s.to_string())
}
