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
package io.contexa.contexacommon.security.bridge;

/**
 * Declares what Contexa's security configuration does to the application. It is a separate setting from
 * {@link SecurityOwnershipMode}, and Contexa runs all of its features in either mode.
 */
public enum SecurityMode {

    /**
     * Contexa is the application's main security configuration: its main chain signs the application's users in, holds
     * their security context and enforces the decisions on their requests.
     */
    FULL,

    /**
     * Contexa is kept apart from an existing application: none of Contexa's security settings (CSRF, CORS, headers, the
     * decision for URLs no policy names) apply to the application's own requests, and Contexa never writes their security
     * context, so the application's sign-in and its own authorization rules stay as they were. Contexa enforces its
     * decisions, and the refusals of the URL policies an operator names for the application's paths, from servlet filters
     * behind the application's chain.
     */
    SANDBOX
}
