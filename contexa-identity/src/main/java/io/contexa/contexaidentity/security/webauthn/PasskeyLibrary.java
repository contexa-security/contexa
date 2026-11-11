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
package io.contexa.contexaidentity.security.webauthn;

import org.springframework.util.ClassUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * Whether passkeys can work in this application. Spring Security's passkey support verifies with webauthn4j and
 * webauthn4j reads its data as CBOR, so a passkey needs both on the class path. An application that excludes them
 * ({@code exclude group: 'com.webauthn4j'}) runs without passkeys, and Spring MVC then no longer registers a CBOR
 * converter for it.
 */
public final class PasskeyLibrary {

    /** The class of webauthn4j that Spring Security's relying party is built on. */
    public static final String WEBAUTHN4J = "com.webauthn4j.WebAuthnManager";

    /** The CBOR codec webauthn4j cannot start without. */
    public static final String CBOR = "com.fasterxml.jackson.dataformat.cbor.CBORFactory";

    private PasskeyLibrary() {
    }

    public static boolean available(ClassLoader loader) {
        return missing(loader).isEmpty();
    }

    /** The libraries a passkey needs and the class path lacks, by the name of the class that is not there. */
    public static List<String> missing(ClassLoader loader) {
        List<String> missing = new ArrayList<>();
        for (String name : List.of(WEBAUTHN4J, CBOR)) {
            if (!ClassUtils.isPresent(name, loader)) {
                missing.add(name);
            }
        }
        return missing;
    }

    /** The one line that says why passkeys are off, or null when they are on. */
    public static String unavailableNotice(ClassLoader loader) {
        List<String> missing = missing(loader);
        if (missing.isEmpty()) {
            return null;
        }
        return "[Contexa] Passkeys are off: " + missing + " is not on the class path (webauthn4j and its CBOR codec "
                + "are excluded from this application). Users verify with the other factors; passkeys already "
                + "registered cannot be used until webauthn4j is back on the class path.";
    }
}
