use std::{collections::BTreeMap, future::Future, net::ToSocketAddrs, sync::Arc, time::Duration};

use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use axum_helpers::{
    app::AxumApp,
    auth::{
        AccessToken, AccessTokenResponse, AuthHandler, AuthLayer, AuthLogoutResponse,
        LoginInfoExtractor, RefreshToken,
    },
};
use clap::Parser;
use parking_lot::Mutex;
use serde_json::json;
use tracing_subscriber::{prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;

const ACCESS_TOKEN_EXPIRATION_TIME_DURATION: Duration = Duration::from_secs(5 * 60 * 60 * 24);

#[derive(Parser)]
#[command()]
pub struct Cli {
    #[arg(
        short('l'),
        long("listener-address"),
        help("Address where the server accepts the connections (e.g., 127.0.0.1:8080)")
    )]
    listener_address: String,
}

#[derive(Clone)]
struct AppState {
    logins: Arc<Mutex<BTreeMap<AccessToken, LoginInfo>>>,
}

impl AppState {
    fn new() -> Self {
        Self {
            logins: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    fn login(
        &mut self,
        loginname: impl Into<String>,
        _password: impl Into<String>,
    ) -> Option<(AccessTokenResponse, LoginInfo)> {
        let loginname = loginname.into();

        let role = match loginname.as_str() {
            "admin" => "admin",
            _ => "regular",
        }
        .into();

        let login_info = LoginInfo { loginname, role };

        let access_token_response = AccessTokenResponse::with_time_delta(
            AccessToken::new(Uuid::new_v4().as_hyphenated().to_string()),
            ACCESS_TOKEN_EXPIRATION_TIME_DURATION,
            None,
        );

        self.logins
            .lock()
            .insert(access_token_response.token().clone(), login_info.clone());

        Some((access_token_response, login_info))
    }

    fn logout(&mut self, access_token: impl AsRef<str>, login_info: &Arc<LoginInfo>) {
        self.logins.lock().remove(access_token.as_ref());

        log::info!("User logged out, loginname = '{}'", login_info.loginname);
    }
}

impl AuthHandler<LoginInfo> for AppState {
    async fn verify_access_token(
        &mut self,
        access_token: &AccessToken,
    ) -> Result<LoginInfo, StatusCode> {
        self.logins
            .lock()
            .get(access_token)
            .cloned()
            .ok_or_else(|| StatusCode::BAD_REQUEST)
    }

    async fn update_access_token(
        &mut self,
        access_token: &AccessToken,
        _login_info: &Arc<LoginInfo>,
    ) -> Option<(AccessToken, Duration)> {
        Some((access_token.clone(), ACCESS_TOKEN_EXPIRATION_TIME_DURATION))
    }

    async fn revoke_access_token(
        &mut self,
        access_token: &AccessToken,
        login_info: &Arc<LoginInfo>,
    ) {
        self.logout(access_token, login_info);
    }

    async fn verify_refresh_token(
        &mut self,
        _refresh_token: &RefreshToken,
    ) -> Result<(), StatusCode> {
        Err(StatusCode::INTERNAL_SERVER_ERROR)
    }

    async fn revoke_refresh_token(&mut self, _refresh_token: &RefreshToken) {}
}

fn routes(state: AppState) -> Router {
    Router::new()
        .route("/", get(index_page))
        .route("/login", get(login_page))
        .route("/api/login", post(api_login))
        .route("/api/logout", post(api_logout))
        .route("/api/logged-in-users", get(api_get_logged_in_users))
        .route_layer(AuthLayer::new(state.clone()))
        .with_state(state)
}

async fn check_required_role<FutureType: Future<Output = impl IntoResponse>>(
    required_role: &str,
    f: impl FnOnce(LoginInfoExtractor<LoginInfo>) -> FutureType,
    LoginInfoExtractor(login_info): LoginInfoExtractor<LoginInfo>,
) -> Result<impl IntoResponse, StatusCode> {
    if login_info.role == required_role {
        Ok(f(LoginInfoExtractor(login_info)).await)
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

async fn index_page(login_info: Option<LoginInfoExtractor<LoginInfo>>) -> Html<String> {
    let header = if login_info.is_some() {
        r#"
            <script>
                async function logout(event) {
                    event.preventDefault();

                    await fetch("/api/logout", {
                        method: "POST",
                    });

                    location.reload();
                }
            </script>
            <form onsubmit="logout(event)">
                <button>Logout</button>
            </form>
        "#
    } else {
        r#"
            <div><a href="/login">Login</a></div>
        "#
    };

    Html(format!(
        r#"
            <html>
                <body>
                    {header}
                    <h1>Endpoints</h1>
                    <ul>
                        <li><b>get /</b>: returns this page</li>
                        <li><b>get /login</b>: returns a page where a user can log in</li>

                        <li><b>post /api/login</b>: logs a user in</li>
                        <li><b>post /api/logout</b>: logs a user out</li>
                    </ul>
                </body>
            </html>
        "#
    ))
}

async fn login_page(login_info: Option<LoginInfoExtractor<LoginInfo>>) -> Html<String> {
    let body_content = if login_info.is_some() {
        r#"
            You are already logged in!
        "#
    } else {
        r#"
            <script>
                async function login(event) {
                    event.preventDefault();

                    let loginname = document.getElementById("loginname").value;
                    let password = document.getElementById("password").value;

                    await fetch("/api/login", {
                        method: "POST",
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({
                            loginname,
                            password,
                        }),
                    });

                    location = "/";
                }
            </script>
            <h1>Login</h1>
            <form onsubmit="login(event)">
                <label for="loginname">Loginname</label>
                <input type="username" id="loginname" />

                <label for="password">Password</label>
                <input type="password" id="password" />

                <button>Login</button>
            </form>
        "#
    };

    Html(format!(
        r#"
            <html>
                <body>
                    {body_content}
                </body>
            </html>
        "#
    ))
}

#[derive(Clone, serde::Serialize)]
struct LoginInfo {
    loginname: String,
    role: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct LoginRequest {
    loginname: String,
    password: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct LoginResponse {
    loginname: String,
}

async fn api_login(
    State(mut state): State<AppState>,
    Json(login_request): Json<LoginRequest>,
) -> Result<(StatusCode, AccessTokenResponse, Json<LoginResponse>), StatusCode> {
    let (access_token_response, _login_info) = state
        .login(&login_request.loginname, login_request.password)
        .ok_or_else(|| StatusCode::BAD_REQUEST)?;

    log::info!("User logged in, loginname = '{}'", login_request.loginname);

    Ok((
        StatusCode::OK,
        access_token_response,
        Json(LoginResponse {
            loginname: login_request.loginname,
        }),
    ))
}

async fn api_logout(
    LoginInfoExtractor(_login_info): LoginInfoExtractor<LoginInfo>,
) -> Result<AuthLogoutResponse, StatusCode> {
    Ok(AuthLogoutResponse::new(Some("/"), Some("/")))
}

#[fn_decorator::use_decorator(check_required_role("admin"), override_return_type = impl IntoResponse, exact_parameters = [_login_info])]
async fn api_get_logged_in_users(
    _login_info: LoginInfoExtractor<LoginInfo>,
    state: State<AppState>,
) -> Json<serde_json::Value> {
    let login_infos = state
        .logins
        .lock()
        .iter()
        .map(|(_access_token, login_info)| login_info.clone())
        .collect::<Vec<_>>();

    Json(json!({
        "login_infos": login_infos
    }))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                "app_with_auth=debug,axum_helpers=debug,tower_http=debug".into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cli = Cli::parse();

    let mut app = AxumApp::new(routes(AppState::new()));
    for addr in cli.listener_address.to_socket_addrs().unwrap() {
        if let Err(e) = app.spawn_server(addr).await {
            log::error!("Could not start server, error = {e:?}");
        }
    }

    app.join().await;
}
