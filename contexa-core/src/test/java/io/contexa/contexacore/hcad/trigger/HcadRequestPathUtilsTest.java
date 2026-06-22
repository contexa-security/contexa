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
package io.contexa.contexacore.hcad.trigger;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;

class HcadRequestPathUtilsTest {

    @Test
    @DisplayName("non-user interaction classification uses request semantics, not URL prefixes")
    void isNonUserInteractionRequest_usesRequestSemanticsNotUrlPrefixes() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/img/logo.png");

        assertThat(HcadRequestPathUtils.isNonUserInteractionRequest(request)).isFalse();

        request.addHeader("Sec-Fetch-Dest", "image");

        assertThat(HcadRequestPathUtils.isNonUserInteractionRequest(request)).isTrue();
    }

    @Test
    @DisplayName("browser asset fetch destinations are excluded without knowing application paths")
    void isNonUserInteractionRequest_assetFetchDestinations_returnsTrue() {
        assertThat(requestWithFetchDest("script")).isTrue();
        assertThat(requestWithFetchDest("style")).isTrue();
        assertThat(requestWithFetchDest("font")).isTrue();
        assertThat(requestWithFetchDest("image")).isTrue();
    }

    @Test
    @DisplayName("document and API fetch destinations remain eligible for HCAD evaluation")
    void isNonUserInteractionRequest_userActionFetchDestinations_returnsFalse() {
        assertThat(requestWithFetchDest("document")).isFalse();
        assertThat(requestWithFetchDest("empty")).isFalse();
    }

    @Test
    @DisplayName("Accept header can identify non-interactive representations when fetch metadata is absent")
    void isNonUserInteractionRequest_acceptHeaderOnlyAssetRepresentations_returnsTrue() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/any/generated/path");
        request.addHeader("Accept", "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8");

        assertThat(HcadRequestPathUtils.isNonUserInteractionRequest(request)).isTrue();
    }

    @Test
    @DisplayName("generic Accept header does not suppress HCAD evaluation")
    void isNonUserInteractionRequest_genericAccept_returnsFalse() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/any/generated/path");
        request.addHeader("Accept", "*/*");

        assertThat(HcadRequestPathUtils.isNonUserInteractionRequest(request)).isFalse();
    }

    @Test
    @DisplayName("CORS preflight is excluded as non-user interaction")
    void isNonUserInteractionRequest_corsPreflight_returnsTrue() {
        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/api/orders");
        request.addHeader("Access-Control-Request-Method", "POST");

        assertThat(HcadRequestPathUtils.isNonUserInteractionRequest(request)).isTrue();
    }

    @Test
    @DisplayName("non-actionable monitoring path classification excludes assets and browser probes without dropping API JSON")
    void isNonActionableMonitoringPath_staticAssetsAndBrowserProbes_returnsTrue() {
        assertThat(HcadRequestPathUtils.isNonActionableMonitoringPath("/img/logo.png")).isTrue();
        assertThat(HcadRequestPathUtils.isNonActionableMonitoringPath("/.well-known/appspecific/com.chrome.devtools.json")).isTrue();
        assertThat(HcadRequestPathUtils.isNonActionableMonitoringPath("/favicon.ico")).isTrue();
        assertThat(HcadRequestPathUtils.isNonActionableMonitoringPath("/api/report.json")).isFalse();
        assertThat(HcadRequestPathUtils.isNonActionableMonitoringPath("/api/orders/1001")).isFalse();
    }

    private boolean requestWithFetchDest(String fetchDest) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/any/generated/path");
        request.addHeader("Sec-Fetch-Dest", fetchDest);
        return HcadRequestPathUtils.isNonUserInteractionRequest(request);
    }
}
