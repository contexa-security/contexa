/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexaidentity.security.core.adapter.state.oauth2;

/**
 * Which requests the security chain of an OAuth2 flow takes (A1-10, AG-12a). Set it with
 * {@code .oauth2(oauth2 -> oauth2.requestScope(OAuth2RequestScope.TOKEN_REQUESTS))}.
 */
public enum OAuth2RequestScope {

    /** Every request the flow covers: all requests, or those under the flow's URL prefix. The default. */
    ALL_REQUESTS,

    /**
     * Only the requests that belong to tokens: requests carrying an access token as the chain reads it (the
     * {@code Authorization: Bearer} header, or the token cookie with the cookie transport), CORS preflights announcing
     * an {@code Authorization} header, the authorization server endpoints and refresh URI this chain hosts, the
     * authentication URLs of the flow, the flow's URL prefix and the requests added with
     * {@link OAuth2StateConfigurer#tokenScopeRequests}. Every other request passes to the next flow, so a session flow
     * ordered after this one keeps serving people's pages while agents and API clients use tokens.
     */
    TOKEN_REQUESTS
}
