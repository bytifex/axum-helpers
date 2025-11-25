use std::future::Future;

use axum::{extract::FromRequestParts, http::StatusCode};

use super::{auth_layer::RefreshTokenVerificationResultExtension, RefreshToken};

pub struct RefreshTokenExtractor(pub RefreshToken);

impl<StateType> FromRequestParts<StateType> for RefreshTokenExtractor {
    type Rejection = StatusCode;

    fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &StateType,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        let refresh_token = parts
            .extensions
            .get::<RefreshTokenVerificationResultExtension>()
            .ok_or(StatusCode::UNAUTHORIZED)
            .and_then(|refresh_token_verification_result_extension| {
                if let Err(status_code) = refresh_token_verification_result_extension.0 .1 {
                    Err(status_code)
                } else {
                    Ok(RefreshTokenExtractor(
                        refresh_token_verification_result_extension.0 .0.clone(),
                    ))
                }
            });

        Box::pin(async move { refresh_token })
    }
}
