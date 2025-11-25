use std::{convert::Infallible, future::Future, sync::Arc};

use axum::{
    extract::{FromRequestParts, OptionalFromRequestParts},
    http::StatusCode,
};

use super::auth_layer::AccessTokenVerificationResultExtension;

pub struct LoginInfoExtractor<LoginInfoType: Clone + Send + Sync + 'static>(pub Arc<LoginInfoType>);

impl<StateType, LoginInfoType> OptionalFromRequestParts<StateType>
    for LoginInfoExtractor<LoginInfoType>
where
    LoginInfoType: Clone + Send + Sync + 'static,
{
    type Rejection = Infallible;

    fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &StateType,
    ) -> impl Future<Output = Result<Option<Self>, Self::Rejection>> + Send {
        let result =
            <LoginInfoExtractor<LoginInfoType> as FromRequestParts<StateType>>::from_request_parts(
                parts, state,
            );
        async move { Ok(result.await.ok()) }
    }
}

impl<StateType, LoginInfoType> FromRequestParts<StateType> for LoginInfoExtractor<LoginInfoType>
where
    LoginInfoType: Clone + Send + Sync + 'static,
{
    type Rejection = StatusCode;

    fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &StateType,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        let login_info = parts
            .extensions
            .get::<AccessTokenVerificationResultExtension<LoginInfoType>>()
            .ok_or(StatusCode::UNAUTHORIZED)
            .and_then(|access_token_verification_result_extension| {
                Ok(LoginInfoExtractor(
                    access_token_verification_result_extension
                        .0
                        .as_ref()?
                        .clone(),
                ))
            });

        async move { login_info }
    }
}
