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
package io.contexa.springbootstartercontexa;

import io.contexa.contexaidentity.security.webauthn.PasskeyLibrary;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** The scenario on the class path of an application that excluded {@code com.webauthn4j} (see the starter's build file). */
class ContexaOwnedWithoutPasskeyLibraryClasspathTest extends ContexaOwnedPasskeyLibraryScenario {

    @Test
    void webauthn4jAndItsCborCodecAreNotOnTheClassPath() {
        assertThat(PasskeyLibrary.missing(getClass().getClassLoader()))
                .containsExactly(PasskeyLibrary.WEBAUTHN4J, PasskeyLibrary.CBOR);
    }
}
