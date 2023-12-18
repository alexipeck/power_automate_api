use axum::{
    extract::ConnectInfo,
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::post,
    Extension, Router,
};
use axum_server::bind;
use parking_lot::RwLock;
use power_automate_api::{cipp, generic, read_lines, VERSION};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet, io::stdout, net::SocketAddr, process::exit, sync::Arc, thread,
    time::Duration,
};
use tokio::signal;
use tracing::{error, info, level_filters::LevelFilter, warn, Level};
use tracing_subscriber::{layer::SubscriberExt, Layer, Registry};

#[derive(Default, Debug)]
struct Keys {
    api_keys: Arc<RwLock<HashSet<String>>>,
}

impl Keys {
    pub fn fill(&self, keys: Vec<String>) {
        self.api_keys.write().extend(keys.into_iter());
    }
    pub fn validate_key(&self, key: &String) -> bool {
        self.api_keys.read().contains(key)
    }
}

#[derive(Deserialize, Debug)]
pub struct Payload {
    pub api_key: String,
    pub email_body: String,
    pub domain_exclusions: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub struct FilterByExclusions {
    pub api_key: String,
    pub strings: Vec<String>,
    pub exclusions: Vec<String>,
}

#[derive(Serialize, Debug)]
pub struct Response {
    filtered_messages: Vec<String>,
    error_messages: Vec<String>,
}

async fn filter_by_exclusions(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(filter_by_exclusions): Json<FilterByExclusions>,
    Extension(api_keys): Extension<Arc<Keys>>,
) -> impl IntoResponse {
    if !api_keys.validate_key(&filter_by_exclusions.api_key) {
        warn!("{} attempted connection with invalid API key.", addr);
        return (StatusCode::UNAUTHORIZED, Json(None));
    }
    info!("Processing message received from {}", addr);

    (
        StatusCode::OK,
        Json(Some(Response {
            filtered_messages: generic::filter_by_exclusions(
                filter_by_exclusions.strings,
                filter_by_exclusions.exclusions,
            ),
            error_messages: Vec::new(),
        })),
    )
}

#[derive(Deserialize, Debug)]
pub struct CIPPAlertData {
    pub api_key: String,
    pub body: String,
    pub domain_exclusions: Vec<String>,
}

async fn parse_messages_from_cipp_alert_body(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(cipp_alert_data): Json<CIPPAlertData>,
    Extension(api_keys): Extension<Arc<Keys>>,
) -> impl IntoResponse {
    if !api_keys.validate_key(&cipp_alert_data.api_key) {
        warn!("{} attempted connection with invalid API key.", addr);
        return (StatusCode::UNAUTHORIZED, Json(None));
    }
    info!("Processing message received from {}", addr);
    match cipp::parse_messages_from_email_alert_body_v1(
        cipp_alert_data.body,
        cipp_alert_data.domain_exclusions,
    ) {
        Ok((filtered_messages, error_messages)) => (
            StatusCode::OK,
            Json(Some(Response {
                filtered_messages,
                error_messages,
            })),
        ),
        Err(err) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(Some(Response {
                filtered_messages: Vec::new(),
                error_messages: vec![err],
            })),
        ),
    }
}

#[tokio::main]
async fn main() {
    //Tracing
    let file =
        tracing_appender::rolling::daily("/logs/", format!("power_automate_api{}.log", VERSION));
    let (stdout_writer, _guard) = tracing_appender::non_blocking(stdout());
    let (file_writer, _guard) = tracing_appender::non_blocking(file);
    let logfile_layer = tracing_subscriber::fmt::layer().with_writer(file_writer);
    let level_filter = LevelFilter::from_level(Level::INFO);
    let stdout_layer = tracing_subscriber::fmt::layer()
        .with_line_number(true)
        .with_writer(stdout_writer)
        .with_filter(level_filter);
    let subscriber = Registry::default().with(stdout_layer).with(logfile_layer);
    tracing::subscriber::set_global_default(subscriber).unwrap();

    //API keys
    let api_keys = Arc::new(Keys::default());
    {
        let mut api_keys_vec: Vec<String> = Vec::new();
        match read_lines("/config/API_KEYS") {
            Ok(lines) => {
                for line in lines {
                    if !line.is_empty() && line.len() > 32 {
                        api_keys_vec.push(line);
                    }
                }
            }
            Err(err) => {
                error!("Exiting: Failed to read API_KEYS file: {}", err);
                thread::sleep(Duration::from_micros(250));
                exit(1);
            }
        }
        if api_keys_vec.is_empty() {
            error!("Exiting: No API keys present");
            thread::sleep(Duration::from_micros(250));
            exit(2);
        }
        api_keys.fill(api_keys_vec);
    };

    let app = Router::new()
        .route(
            "/generic/filter_by_exclusions",
            post(
                |connect_info: ConnectInfo<SocketAddr>,
                 api_keys: Extension<Arc<Keys>>,
                 payload: Json<FilterByExclusions>| async move {
                    filter_by_exclusions(connect_info, payload, api_keys).await
                },
            ),
        )
        .route(
            "/cipp/parse_messages_from_email_alert_body",
            post(
                |connect_info: ConnectInfo<SocketAddr>,
                 api_keys: Extension<Arc<Keys>>,
                 payload: Json<CIPPAlertData>| async move {
                    parse_messages_from_cipp_alert_body(connect_info, payload, api_keys).await
                },
            ),
        )
        .layer(Extension(api_keys));

    let addr = SocketAddr::from(([0, 0, 0, 0], 2458));
    info!("REST API endpoint listening on {}", addr);
    tokio::select! {
        _ = bind(addr)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>()) => {},
        _ = signal::ctrl_c() => {},
    }
}
