use std::{borrow::Borrow, future::Future, ops::Deref, sync::Arc};

use axum::http::StatusCode;
use tokio::time::Duration;

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct AccessToken(pub(super) String);

impl AccessToken {
    pub fn new(token: String) -> Self {
        Self(token)
    }
}

impl Deref for AccessToken {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Borrow<str> for AccessToken {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl Borrow<String> for AccessToken {
    fn borrow(&self) -> &String {
        &self.0
    }
}

impl From<AccessToken> for String {
    fn from(token: AccessToken) -> Self {
        token.0
    }
}

impl AsRef<str> for AccessToken {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct RefreshToken(pub(super) String);

impl RefreshToken {
    pub fn new(token: String) -> Self {
        Self(token)
    }
}

impl Deref for RefreshToken {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Borrow<str> for RefreshToken {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl Borrow<String> for RefreshToken {
    fn borrow(&self) -> &String {
        &self.0
    }
}

impl From<RefreshToken> for String {
    fn from(token: RefreshToken) -> Self {
        token.0
    }
}

impl AsRef<str> for RefreshToken {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

pub trait AuthHandler<LoginInfoType: Send + Sync>: Sized + Clone + Send + Sync + 'static {
    /// Verify access token is called for every request that contains an access token
    /// and is expected to return the associated login info if the token is valid.
    /// If the token is invalid, an error with the appropriate status code is returned.
    fn verify_access_token(
        &mut self,
        access_token: &AccessToken,
    ) -> impl Future<Output = Result<LoginInfoType, StatusCode>> + Send;

    /// Update access token is called for every request that contains a valid access token.
    /// The returned access token is sent for the client.
    fn update_access_token(
        &mut self,
        access_token: &AccessToken,
        login_info: &Arc<LoginInfoType>,
    ) -> impl Future<Output = Option<(AccessToken, Duration)>> + Send;

    /// Revoke access token is called when the auth layer receives a logout response from a request handler.
    fn revoke_access_token(
        &mut self,
        access_token: &AccessToken,
        login_info: &Arc<LoginInfoType>,
    ) -> impl Future<Output = ()> + Send;

    /// Verify refresh token is called for every request that contains a refresh token.
    /// If the token is invalid, an error with the appropriate status code is returned.
    fn verify_refresh_token(
        &mut self,
        refresh_token: &RefreshToken,
    ) -> impl Future<Output = Result<(), StatusCode>> + Send;

    /// Revoke refresh token is called when the auth layer receives a logout response from a request handler.
    fn revoke_refresh_token(
        &mut self,
        refresh_token: &RefreshToken,
    ) -> impl Future<Output = ()> + Send;
}
