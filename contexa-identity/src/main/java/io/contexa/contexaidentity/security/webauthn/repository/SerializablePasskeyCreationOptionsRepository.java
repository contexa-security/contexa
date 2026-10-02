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
package io.contexa.contexaidentity.security.webauthn.repository;

import io.contexa.contexaidentity.security.webauthn.codec.PasskeyCreationOptionsCodec;
import io.contexa.contexaidentity.security.webauthn.state.PasskeyCreationOptionsState;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions;
import org.springframework.security.web.webauthn.registration.PublicKeyCredentialCreationOptionsRepository;

import java.util.Objects;

public final class SerializablePasskeyCreationOptionsRepository
        implements PublicKeyCredentialCreationOptionsRepository {

    private static final String ATTRIBUTE_NAME = PublicKeyCredentialCreationOptions.class.getName() + "ATTR_NAME";

    private final PasskeyCreationOptionsCodec codec;

    public SerializablePasskeyCreationOptionsRepository(PasskeyCreationOptionsCodec codec) {
        this.codec = Objects.requireNonNull(codec);
    }

    @Override
    public void save(HttpServletRequest request, HttpServletResponse response,
            PublicKeyCredentialCreationOptions options) {
        request.getSession().setAttribute(ATTRIBUTE_NAME, options == null ? null : codec.encode(options));
    }

    @Override
    public PublicKeyCredentialCreationOptions load(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return null;
        }
        Object value = session.getAttribute(ATTRIBUTE_NAME);
        if (value == null) {
            return null;
        }
        if (value instanceof PublicKeyCredentialCreationOptions options) {
            return options;
        }
        if (value instanceof PasskeyCreationOptionsState state) {
            return codec.decode(state);
        }
        throw new IllegalStateException("Unsupported passkey creation options session value");
    }
}
