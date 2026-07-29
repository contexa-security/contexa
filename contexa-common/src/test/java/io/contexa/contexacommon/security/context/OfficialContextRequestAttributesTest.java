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
package io.contexa.contexacommon.security.context;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class OfficialContextRequestAttributesTest {

    @Test
    void canonicalAttributeTakesPrecedenceOverNeutralAttribute() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute(OfficialContextField.MFA_VERIFIED.canonicalAttributeKey(), true);
        request.setAttribute("mfaVerified", false);

        assertThat(OfficialContextRequestAttributes.extractSnapshot(request))
                .containsEntry("mfaVerified", true);
    }

    @Test
    void neutralAttributeRemainsReadable() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute("failedLoginAttempts", 4);

        assertThat(OfficialContextRequestAttributes.extractSnapshot(request))
                .containsEntry("failedLoginAttempts", 4);
    }

    @Test
    void snapshotProjectionWritesCanonicalAttributeWithoutChangingMetadataKey() {
        MockHttpServletRequest request = new MockHttpServletRequest();

        OfficialContextRequestAttributes.applySnapshot(
                request,
                Map.of("deviceBrowser", "Firefox"),
                true);

        assertThat(request.getAttribute("ctxa.context.deviceBrowser")).isEqualTo("Firefox");
        assertThat(OfficialContextRequestAttributes.extractSnapshot(request))
                .containsExactlyEntriesOf(Map.of("deviceBrowser", "Firefox"));
    }
}
