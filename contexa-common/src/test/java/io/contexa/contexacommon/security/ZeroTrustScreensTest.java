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
package io.contexa.contexacommon.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ZeroTrustScreensTest {

    /**
     * Ownership browser check 2026-11-03: under a BLOCK or an ESCALATE the screen's own scripts and styles were sent back
     * to the screen (a 302 with the HTML of the page as the script), so the release request of the block screen and the
     * live update of the pending screen never ran, in FULL as in HOST_OWNED.
     */
    @Test
    @DisplayName("the files a screen of a decision loads are not stopped by the decision")
    void theScreensOwnFilesAreNotStopped() {
        assertThat(ZeroTrustScreens.isScreenResource("/contexa/js/zero-trust/blocked.js")).isTrue();
        assertThat(ZeroTrustScreens.isScreenResource("/contexa/js/toast.js")).isTrue();
        assertThat(ZeroTrustScreens.isScreenResource("/contexa/css/main.css")).isTrue();
        assertThat(ZeroTrustScreens.isScreenResource("/contexa/img/logo.png")).isTrue();
    }

    @Test
    @DisplayName("nothing else under /contexa, and nothing of the application, passes as a screen file")
    void nothingElsePasses() {
        assertThat(ZeroTrustScreens.isScreenResource("/contexa/admin/dashboard")).isFalse();
        assertThat(ZeroTrustScreens.isScreenResource("/contexa/api/agent-delegations")).isFalse();
        assertThat(ZeroTrustScreens.isScreenResource("/js/app.js")).isFalse();
        assertThat(ZeroTrustScreens.isScreenResource("/api/contexa/js/x")).isFalse();
        assertThat(ZeroTrustScreens.isScreenResource("/contexa/jsx/evil")).isFalse();
        assertThat(ZeroTrustScreens.isScreenResource("/contexa/js/../admin/api/agents")).isFalse();
        assertThat(ZeroTrustScreens.isScreenResource(null)).isFalse();
    }

    /** The skip must not be a way round the decision: every spelling that leaves the folder is not a screen file. */
    @Test
    @DisplayName("a path that leaves the folder by encoding, a dot segment or a path parameter is not a screen file")
    void aWayOutOfTheFolderIsNotAScreenFile() {
        assertThat(ZeroTrustScreens.isScreenResource("/contexa/js/%2e%2e/admin/api/agents")).isFalse();
        assertThat(ZeroTrustScreens.isScreenResource("/contexa/js/..%2fadmin")).isFalse();
        assertThat(ZeroTrustScreens.isScreenResource("/contexa/js/..;/admin")).isFalse();
        assertThat(ZeroTrustScreens.isScreenResource("/contexa/css/a.css;jsessionid=1")).isFalse();
        assertThat(ZeroTrustScreens.isScreenResource("/contexa/js\\..\\admin")).isFalse();
        assertThat(ZeroTrustScreens.isScreenResource("/contexa/js//admin")).isFalse();
        assertThat(ZeroTrustScreens.isScreenResource("/contexa/js/")).isFalse();
    }
}
