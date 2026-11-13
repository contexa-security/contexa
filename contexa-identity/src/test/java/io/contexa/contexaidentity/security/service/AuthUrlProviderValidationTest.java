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
package io.contexa.contexaidentity.security.service;

import io.contexa.contexacommon.properties.AuthContextProperties;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Two address settings with one value took one request for two endpoints, and one of them was gone without a word:
 * the selection answered the cancel, a refresh address equal to a sign-in address refreshed nothing (P-2).
 */
class AuthUrlProviderValidationTest {

    @Test
    void theDefaultAddressesStart() {
        assertThatCode(() -> new AuthUrlProvider(new AuthContextProperties()).validateConfiguration())
                .doesNotThrowAnyException();
    }

    @Test
    void theFactorSelectionAtTheCancelAddressStopsTheStart() {
        AuthContextProperties properties = new AuthContextProperties();
        properties.getUrls().getMfa().setSelectFactor("/mfa/cancel");

        assertThatThrownBy(() -> new AuthUrlProvider(properties).validateConfiguration())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("URL is used by more than one endpoint: /mfa/cancel")
                .hasMessageContaining("Mfa.selectFactor")
                .hasMessageContaining("Give each its own address");
    }

    @Test
    void theRefreshAddressAtASignInAddressStopsTheStart() {
        AuthContextProperties properties = new AuthContextProperties();
        properties.getInternal().setRefreshUri(properties.getUrls().getSingle().getRestLoginProcessing());

        assertThatThrownBy(() -> new AuthUrlProvider(properties).validateConfiguration())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Internal.refreshUri");
    }

    /** A GET shows the page and a POST signs in: the sign-in page may be where its form posts. */
    @Test
    void theSignInPageMayBeWhereItsFormPosts() {
        AuthContextProperties properties = new AuthContextProperties();
        properties.getUrls().getPrimary().setFormLoginPage("/signin");
        properties.getUrls().getPrimary().setFormLoginProcessing("/signin");

        assertThatCode(() -> new AuthUrlProvider(properties).validateConfiguration()).doesNotThrowAnyException();
    }
}
