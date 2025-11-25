use std::{collections::BTreeMap, sync::Arc, time::Duration};

use async_trait::async_trait;
use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};

use crate::{
    app::AxumApp,
    auth::{
        AccessToken, AccessTokenResponse, AuthHandler, AuthLayer, AuthLogoutResponse,
        LoginInfoExtractor, RefreshToken,
    },
};
use parking_lot::Mutex;
use uuid::Uuid;

const ACCESS_TOKEN_EXPIRATION_TIME_DURATION: Duration = Duration::from_secs(1);

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

        let login_info = LoginInfo { loginname };

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

    fn logout(&mut self, access_token: &AccessToken, login_info: &Arc<LoginInfo>) {
        self.logins.lock().remove(access_token);

        log::info!("User logged out, loginname = '{}'", login_info.loginname);
    }
}

#[async_trait]
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
        unreachable!("tests contained in this file, this line should not be called")
    }

    async fn revoke_refresh_token(&mut self, _refresh_token: &RefreshToken) {
        unreachable!("tests contained in this file, this line should not be called")
    }
}

fn routes(state: AppState) -> Router {
    Router::new()
        .route("/public", get(get_public))
        .route("/private", get(get_private))
        .route("/hybrid", get(get_hybrid))
        .route("/api/login", post(api_login))
        .route("/api/logout", post(api_logout))
        .route_layer(AuthLayer::new(state.clone()))
        .with_state(state)
}

async fn get_public() -> &'static str {
    "public"
}

async fn get_private(
    LoginInfoExtractor(_login_info): LoginInfoExtractor<LoginInfo>,
) -> &'static str {
    "private"
}

async fn get_hybrid(login_info: Option<LoginInfoExtractor<LoginInfo>>) -> &'static str {
    if login_info.is_some() {
        "authenticated"
    } else {
        "unauthenticated"
    }
}

#[derive(Clone)]
struct LoginInfo {
    loginname: String,
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
    let (access_token, _login_info) = state
        .login(&login_request.loginname, login_request.password)
        .ok_or_else(|| StatusCode::BAD_REQUEST)?;

    log::info!("User logged in, loginname = '{}'", login_request.loginname);

    Ok((
        StatusCode::OK,
        access_token,
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

#[tokio::test]
async fn get_public_page() {
    let app = AxumApp::new(routes(AppState::new()));
    let server = app.spawn_test_server().unwrap();

    let response = server.get("/public").await;
    response.assert_status_ok();
    response.assert_text("public");
}

#[tokio::test]
async fn get_private_page_unauthenticated() {
    let app = AxumApp::new(routes(AppState::new()));
    let server = app.spawn_test_server().unwrap();

    let response = server.get("/private").await;
    response.assert_status_unauthorized();
}

#[tokio::test]
async fn get_private_page_authenticated() {
    let app = AxumApp::new(routes(AppState::new()));
    let mut server = app.spawn_test_server().unwrap();
    server.save_cookies();

    server
        .post("/api/login")
        .json(&LoginRequest {
            loginname: "loginname".into(),
            password: "password".into(),
        })
        .await;

    let response = server.get("/private").await;
    response.assert_text("private");
}

#[tokio::test]
async fn get_hybrid_page_unauthenticated() {
    let app = AxumApp::new(routes(AppState::new()));
    let server = app.spawn_test_server().unwrap();

    let response = server.get("/hybrid").await;
    response.assert_status_ok();
    response.assert_text("unauthenticated");
}

#[tokio::test]
async fn get_hybrid_page_authenticated() {
    let app = AxumApp::new(routes(AppState::new()));
    let mut server = app.spawn_test_server().unwrap();
    server.save_cookies();

    server
        .post("/api/login")
        .json(&LoginRequest {
            loginname: "loginname".into(),
            password: "password".into(),
        })
        .await;

    let response = server.get("/hybrid").await;
    response.assert_status_ok();
    response.assert_text("authenticated");
}

#[tokio::test]
async fn expired_access_token() {
    let app = AxumApp::new(routes(AppState::new()));
    let mut server = app.spawn_test_server().unwrap();
    server.save_cookies();

    server
        .post("/api/login")
        .json(&LoginRequest {
            loginname: "loginname".into(),
            password: "password".into(),
        })
        .await;

    let response = server.get("/private").await;
    response.assert_status_ok();
    response.assert_text("private");

    std::thread::sleep(Duration::from_secs(1));

    let response = server.get("/private").await;
    response.assert_status_unauthorized();
}

#[tokio::test]
async fn login_then_logout() {
    let app = AxumApp::new(routes(AppState::new()));
    let mut server = app.spawn_test_server().unwrap();
    server.save_cookies();

    let response = server.get("/hybrid").await;
    response.assert_status_ok();
    response.assert_text("unauthenticated");

    server
        .post("/api/login")
        .json(&LoginRequest {
            loginname: "loginname".into(),
            password: "password".into(),
        })
        .await;

    let response = server.get("/hybrid").await;
    response.assert_status_ok();
    response.assert_text("authenticated");

    server.post("/api/logout").await;

    let response = server.get("/hybrid").await;
    response.assert_status_ok();
    response.assert_text("unauthenticated");
}
