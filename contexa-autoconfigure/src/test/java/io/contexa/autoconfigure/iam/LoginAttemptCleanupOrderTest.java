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
package io.contexa.autoconfigure.iam;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.security.SecurityProperties;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * PR-69: a failed sign-in ends inside the security chain and never reaches a filter behind it, so the marker of the
 * failure stayed on the worker thread, and the next failure of the same name on that thread was not counted: one name
 * repeated from one address never reached the limit.
 */
class LoginAttemptCleanupOrderTest {

    @Test
    @DisplayName("the cleanup of the login policy surrounds the security chain")
    void theCleanupSurroundsTheSecurityChain() {
        int order = new IamSecurityCoreContexaOwnedConfiguration().loginAttemptCleanupFilterRegistration().getOrder();

        assertThat(order).isLessThan(SecurityProperties.DEFAULT_FILTER_ORDER);
    }
}
