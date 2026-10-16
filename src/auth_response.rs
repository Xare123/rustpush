//! Response boundary for account/delegate, IDS certificate and service-bag calls.
//! No response body, URL, header, account identifier or parser error is logged.
use std::time::Duration;

use plist::{Dictionary, Value};
use reqwest::{Response, StatusCode};

use crate::PushError;

const MAX_AUTH_RESPONSE_BYTES: usize = 1024 * 1024;
const AUTH_RESPONSE_TIMEOUT: Duration = Duration::from_secs(15);

pub(crate) struct AuthResponse {
    pub dictionary: Dictionary,
    stage: &'static str,
    status: StatusCode,
    bytes: usize,
}

impl AuthResponse {
    pub async fn read(stage: &'static str, response: Response) -> Result<Self, PushError> {
        Self::read_with_timeout(stage, response, AUTH_RESPONSE_TIMEOUT).await
    }

    async fn read_with_timeout(
        stage: &'static str,
        mut response: Response,
        deadline: Duration,
    ) -> Result<Self, PushError> {
        let mut result = Self {
            dictionary: Dictionary::new(),
            stage,
            status: response.status(),
            bytes: 0,
        };
        if response
            .content_length()
            .is_some_and(|length| length > MAX_AUTH_RESPONSE_BYTES as u64)
        {
            return Err(result.failure("body-too-large"));
        }
        let mut body = Vec::new();
        let read = tokio::time::timeout(deadline, async {
            loop {
                let chunk = response.chunk().await.map_err(|_| "incomplete-body")?;
                let Some(chunk) = chunk else {
                    return Ok::<(), &'static str>(());
                };
                if chunk.len() > MAX_AUTH_RESPONSE_BYTES - body.len() {
                    return Err("body-too-large");
                }
                body.extend_from_slice(&chunk);
            }
        })
        .await;
        result.bytes = body.len();
        match read {
            Err(_) => return Err(result.failure("body-timeout")),
            Ok(Err(reason)) => return Err(result.failure(reason)),
            Ok(Ok(())) => {}
        }
        if body.is_empty() {
            return Err(result.failure("empty-body"));
        }
        // A plist may be binary. Decoding through Response::text first corrupts
        // its bytes and turns a valid response into a misleading parser failure.
        let value: Value = plist::from_bytes(&body).map_err(|_| result.failure("invalid-plist"))?;
        result.dictionary = value
            .into_dictionary()
            .ok_or_else(|| result.failure("invalid-root"))?;
        // Preserve explicit service rejections (including terms/account errors)
        // even when Apple uses a non-2xx HTTP status. Never accept status=0 on
        // an HTTP failure just because the body looks like a success plist.
        let rejected = result
            .dictionary
            .get("localizedError")
            .and_then(Value::as_string)
            .is_some_and(|error| !error.is_empty())
            || result.dictionary.get("status").is_some_and(|status| {
                status.as_signed_integer().is_some_and(|code| code != 0)
                    || status.as_unsigned_integer().is_some_and(|code| code != 0)
            });
        if !result.status.is_success() && !rejected {
            return Err(result.failure("http-error"));
        }
        Ok(result)
    }

    pub fn failure(&self, reason: &'static str) -> PushError {
        let error = PushError::AppleAuthResponse {
            stage: self.stage,
            status: self.status.as_u16(),
            reason,
            bytes: self.bytes,
        };
        log::warn!("{error}");
        error
    }

    // read() permits structured rejections through for endpoint-specific error
    // handling. Every endpoint must call this before accepting success fields.
    pub fn require_http_success(&self) -> Result<(), PushError> {
        if !self.status.is_success() {
            return Err(self.failure("http-error"));
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "auth_response_tests.rs"]
mod tests;
