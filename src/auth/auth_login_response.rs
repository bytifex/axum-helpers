use axum::response::{IntoResponse, IntoResponseParts, Response, ResponseParts};
use axum_extra::extract::CookieJar;

use super::{auth_layer::create_auth_cookie, AccessTokenInfo};

pub struct AuthLoginResponse {
    access_token_info: AccessTokenInfo,
}

impl AuthLoginResponse {
    pub fn new(
        access_token_info: AccessTokenInfo,
    ) -> Self {
        Self {
            access_token_info,
        }
    }
}

impl IntoResponseParts for AuthLoginResponse {
    type Error = <CookieJar as IntoResponseParts>::Error;

    fn into_response_parts(
        self,
        res: axum::response::ResponseParts,
    ) -> Result<ResponseParts, Self::Error> {
        let cookie = create_auth_cookie(
            self.access_token_info.0.token,
            self.access_token_info.0.expires_at,
            self.access_token_info.0.path,
        );

        CookieJar::new().add(cookie).into_response_parts(res)
    }
}

impl IntoResponse for AuthLoginResponse {
    fn into_response(self) -> Response {
        (self, ()).into_response()
    }
}
