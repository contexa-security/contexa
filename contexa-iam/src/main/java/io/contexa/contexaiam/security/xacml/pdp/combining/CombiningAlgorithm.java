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
package io.contexa.contexaiam.security.xacml.pdp.combining;

/**
 * XACML 3.0 standard combining algorithms for policy evaluation.
 * Determines how multiple matching policies are combined into a single decision.
 */
public enum CombiningAlgorithm {

    /**
     * If any matching policy returns DENY, the result is DENY.
     * Most secure option - recommended as default.
     */
    DENY_OVERRIDES,

    /**
     * If any matching policy returns ALLOW, the result is ALLOW.
     */
    PERMIT_OVERRIDES,

    /**
     * The first matching policy determines the result.
     * Original behavior before combining algorithm support.
     */
    FIRST_APPLICABLE,

    /**
     * Unless an explicit ALLOW is found, the result is DENY.
     */
    DENY_UNLESS_PERMIT
}
