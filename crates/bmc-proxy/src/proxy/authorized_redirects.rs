/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Opt-in redirect traversal with the original caller's ACL checked before
//! each subsequent request. One admission slot covers the complete exchange.

use std::net::IpAddr;
use std::time::Duration;

use carbide_instrument::emit;
use http::uri::PathAndQuery;
use http::{Method, StatusCode, header};

use crate::config::RedirectMode;
use crate::metrics::{
    MethodLabel, RedirectDisposition, RedirectObserved, RedirectStatus, RedirectTarget,
    RequestPathRejected, UpstreamAuthRetried,
};
use crate::proxy::credentials::evict_cached_credentials;
use crate::proxy::guard::path_rejection_reason;
use crate::proxy::response::{BmcOrigins, RedirectLocation, redirect_location};
use crate::proxy::upstream::{
    AttemptFailed, MAX_REDIRECTS, UpstreamBody, UpstreamResponse, send_upstream,
};
use crate::proxy::{BmcProxyState, error_response};

/// Follows at most five same-origin redirects, authorizing the effective method
/// and resolved path before each hop. A single credential refresh retries only
/// the rejected hop. Each followed redirect adds half the original class budget
/// to the existing deadline, retaining unused time.
pub(super) async fn send_authorized_upstream(
    state: &BmcProxyState,
    target_ip: IpAddr,
    parts: &http::request::Parts,
    principals: &[String],
    upstream_body: &mut UpstreamBody,
    deadline: tokio::time::Instant,
    class_budget: Duration,
) -> Result<UpstreamResponse, AttemptFailed> {
    let mut parts = parts.clone();
    let mut path_and_query = parts
        .uri
        .path_and_query()
        .cloned()
        .ok_or_else(|| error_response((StatusCode::BAD_REQUEST, "missing path").into()))?;
    let may_refresh = upstream_body.is_replayable();
    let mut chain_deadline = upstream_body
        .streamed_timeout()
        .map_or(deadline, |timeout| deadline + timeout);
    let mut hop_deadline = deadline;
    let mut refreshed = false;
    let mut followed = 0;
    let mut prior_bmc_time = Duration::ZERO;
    let mut sensitive_values = Vec::new();

    let mut final_response = loop {
        let mut upstream = send_upstream(
            state,
            target_ip,
            &parts,
            path_and_query.clone(),
            upstream_body,
            hop_deadline,
        )
        .await
        .map_err(|failed| failed.with_prior_bmc_time(prior_bmc_time))?;
        prior_bmc_time = prior_bmc_time.saturating_add(upstream.took);
        sensitive_values.append(&mut upstream.sensitive_values);
        let response = &upstream.response;
        let status = response.status();
        if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN)
            && may_refresh
            && !refreshed
        {
            evict_cached_credentials(target_ip, &state.credential_cache).await;
            emit(UpstreamAuthRetried {
                method: MethodLabel::from(&parts.method),
                bmc_ip_address: target_ip.to_string(),
            });
            refreshed = true;
            chain_deadline = tokio::time::Instant::now() + class_budget;
            hop_deadline = chain_deadline;
            prior_bmc_time = Duration::ZERO;
            continue;
        }

        let Some((method, drop_body)) = redirect_method(status, &parts.method) else {
            break upstream;
        };
        if !drop_body && !upstream_body.is_replayable() {
            break upstream;
        }
        let mut locations = response.headers().get_all(header::LOCATION).iter();
        let Some(location) = locations.next() else {
            break upstream;
        };
        if locations.next().is_some() {
            // The response layer rejects duplicate Locations without contacting
            // either target, using the same sanitization as the existing modes.
            break upstream;
        }
        let origins = BmcOrigins::new(response.url().clone(), target_ip);
        let RedirectLocation::Relative(relative, RedirectTarget::SameOrigin) =
            redirect_location(location, &origins, &sensitive_values)
        else {
            // Unsafe targets are rejected by the response layer. A direct BMC
            // target behind a chained proxy is safely returned to the caller.
            break upstream;
        };
        if followed == MAX_REDIRECTS {
            observe_redirect(status, RedirectDisposition::LimitExceeded);
            return Err(error_response(
                (StatusCode::BAD_GATEWAY, "too many authorized BMC redirects").into(),
            )
            .into());
        }
        let relative = relative.to_str().map_err(|_| {
            error_response((StatusCode::BAD_GATEWAY, "invalid redirect target").into())
        })?;
        // Fragments belong to the client and are never part of an HTTP request.
        let path_and_fragment = relative.split_once('#').map_or(relative, |(path, _)| path);
        let next_path: PathAndQuery = path_and_fragment.parse().map_err(|_| {
            error_response((StatusCode::BAD_GATEWAY, "invalid redirect path").into())
        })?;
        if let Some(reason) = path_rejection_reason(next_path.path()) {
            emit(RequestPathRejected::new(
                &method,
                next_path.path().to_string(),
                reason,
            ));
            observe_redirect(status, RedirectDisposition::Rejected);
            return Err(error_response(
                (
                    StatusCode::BAD_GATEWAY,
                    "redirect URL path is ambiguous or contains an invalid escape",
                )
                    .into(),
            )
            .into());
        }
        if !state.authorize_method_path(principals, &method, next_path.path()) {
            observe_redirect(status, RedirectDisposition::Rejected);
            return Err(error_response(
                (StatusCode::FORBIDDEN, "redirect target is not authorized").into(),
            )
            .into());
        }
        if drop_body {
            *upstream_body = UpstreamBody::None;
            // RFC 9110 section 15.4 removes metadata for the discarded
            // representation, including fields beyond Reqwest's framing set.
            for name in [
                header::CONTENT_TYPE,
                header::CONTENT_LENGTH,
                header::CONTENT_ENCODING,
                header::CONTENT_LANGUAGE,
                header::CONTENT_LOCATION,
                header::CONTENT_RANGE,
                header::LAST_MODIFIED,
                header::TRANSFER_ENCODING,
                header::EXPECT,
                http::HeaderName::from_static("digest"),
                http::HeaderName::from_static("content-digest"),
                http::HeaderName::from_static("repr-digest"),
                http::HeaderName::from_static("content-md5"),
            ] {
                parts.headers.remove(name);
            }
        }
        let mut referer = response.url().clone();
        referer.set_fragment(None);
        if let Ok(value) = http::HeaderValue::from_str(referer.as_str()) {
            parts.headers.insert(header::REFERER, value);
        }
        parts.method = method;
        path_and_query = next_path;
        chain_deadline += class_budget / 2;
        hop_deadline = chain_deadline;
        followed += 1;
        observe_redirect(status, RedirectDisposition::Followed);
    };
    final_response.sensitive_values = sensitive_values;
    Ok(final_response)
}

/// Reqwest's redirect method and body semantics, applied before ACL matching.
/// The boolean indicates that the body and its framing headers must be removed.
fn redirect_method(status: StatusCode, method: &Method) -> Option<(Method, bool)> {
    match status {
        StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND if *method == Method::POST => {
            Some((Method::GET, true))
        }
        StatusCode::SEE_OTHER => Some((
            if *method == Method::HEAD {
                Method::HEAD
            } else {
                Method::GET
            },
            true,
        )),
        StatusCode::MOVED_PERMANENTLY
        | StatusCode::FOUND
        | StatusCode::TEMPORARY_REDIRECT
        | StatusCode::PERMANENT_REDIRECT => Some((method.clone(), false)),
        _ => None,
    }
}

/// Records the bounded redirect labels for the opt-in traversal mode.
fn observe_redirect(status: StatusCode, disposition: RedirectDisposition) {
    emit(RedirectObserved {
        mode: RedirectMode::FollowAuthorized,
        status: RedirectStatus::from(status),
        target: RedirectTarget::SameOrigin,
        disposition,
    });
}

#[cfg(test)]
mod tests {
    use carbide_test_support::value_scenarios;
    use http::{Method, StatusCode};

    use super::redirect_method;

    /// The effective method and body determine the ACL and replay contract.
    #[test]
    fn redirect_methods_follow_the_reqwest_contract() {
        value_scenarios!(
            run = |(status, method)| redirect_method(status, &method);
            "POST becomes a bodyless GET" {
                (StatusCode::MOVED_PERMANENTLY, Method::POST) => Some((Method::GET, true)),
            }
            "other methods retain their body on 302" {
                (StatusCode::FOUND, Method::PATCH) => Some((Method::PATCH, false)),
            }
            "303 removes the body and preserves HEAD" {
                (StatusCode::SEE_OTHER, Method::PUT) => Some((Method::GET, true)),
                (StatusCode::SEE_OTHER, Method::HEAD) => Some((Method::HEAD, true)),
            }
            "307 and 308 retain the method and body" {
                (StatusCode::TEMPORARY_REDIRECT, Method::POST) => Some((Method::POST, false)),
                (StatusCode::PERMANENT_REDIRECT, Method::PUT) => Some((Method::PUT, false)),
            }
            "304 is not followed" {
                (StatusCode::NOT_MODIFIED, Method::GET) => None,
            }
        );
    }
}
