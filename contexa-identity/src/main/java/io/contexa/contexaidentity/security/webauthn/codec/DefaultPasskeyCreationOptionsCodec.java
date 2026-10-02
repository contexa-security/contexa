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
package io.contexa.contexaidentity.security.webauthn.codec;

import io.contexa.contexaidentity.security.webauthn.state.PasskeyAuthenticatorSelectionState;
import io.contexa.contexaidentity.security.webauthn.state.PasskeyCreationOptionsState;
import org.springframework.security.web.webauthn.api.AttestationConveyancePreference;
import org.springframework.security.web.webauthn.api.AuthenticatorAttachment;
import org.springframework.security.web.webauthn.api.AuthenticatorSelectionCriteria;
import org.springframework.security.web.webauthn.api.AuthenticatorTransport;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialDescriptor;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialParameters;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRpEntity;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialType;
import org.springframework.security.web.webauthn.api.ResidentKeyRequirement;
import org.springframework.security.web.webauthn.api.UserVerificationRequirement;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public final class DefaultPasskeyCreationOptionsCodec implements PasskeyCreationOptionsCodec {

    private static final List<PublicKeyCredentialParameters> PARAMETERS = List.of(
            PublicKeyCredentialParameters.EdDSA, PublicKeyCredentialParameters.ES256,
            PublicKeyCredentialParameters.ES384, PublicKeyCredentialParameters.ES512,
            PublicKeyCredentialParameters.RS256, PublicKeyCredentialParameters.RS384,
            PublicKeyCredentialParameters.RS512, PublicKeyCredentialParameters.RS1);

    @Override
    public PasskeyCreationOptionsState encode(PublicKeyCredentialCreationOptions options) {
        AuthenticatorSelectionCriteria selection = options.getAuthenticatorSelection();
        PasskeyAuthenticatorSelectionState storedSelection = selection == null ? null
                : new PasskeyAuthenticatorSelectionState(
                        selection.getAuthenticatorAttachment() == null ? null
                                : selection.getAuthenticatorAttachment().getValue(),
                        selection.getResidentKey() == null ? null : selection.getResidentKey().getValue(),
                        selection.getUserVerification() == null ? null
                                : selection.getUserVerification().getValue());
        return new PasskeyCreationOptionsState(
                options.getRp().getId(), options.getRp().getName(), options.getUser(), options.getChallenge(),
                options.getPubKeyCredParams().stream().map(this::algorithmId).toList(), options.getTimeout(),
                options.getExcludeCredentials(), storedSelection,
                options.getAttestation() == null ? null : options.getAttestation().getValue(),
                options.getExtensions());
    }

    @Override
    public PublicKeyCredentialCreationOptions decode(PasskeyCreationOptionsState state) {
        return PublicKeyCredentialCreationOptions.builder()
                .rp(PublicKeyCredentialRpEntity.builder().id(state.rpId()).name(state.rpName()).build())
                .user(state.user())
                .challenge(state.challenge())
                .pubKeyCredParams(state.algorithmIds().stream().map(this::parameter).toList())
                .timeout(state.timeout())
                .excludeCredentials(state.excludeCredentials() == null ? null
                        : state.excludeCredentials().stream().map(this::descriptor).toList())
                .authenticatorSelection(selection(state.authenticatorSelection()))
                .attestation(state.attestation() == null ? null
                        : AttestationConveyancePreference.valueOf(state.attestation()))
                .extensions(state.extensions())
                .build();
    }

    private long algorithmId(PublicKeyCredentialParameters parameter) {
        if (!PublicKeyCredentialType.PUBLIC_KEY.getValue().equals(parameter.getType().getValue())) {
            throw new IllegalArgumentException("Unsupported passkey credential type");
        }
        long algorithmId = parameter.getAlg().getValue();
        parameter(algorithmId);
        return algorithmId;
    }

    private PublicKeyCredentialParameters parameter(long algorithmId) {
        return PARAMETERS.stream()
                .filter(parameter -> parameter.getAlg().getValue() == algorithmId)
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unsupported passkey credential algorithm"));
    }

    private PublicKeyCredentialDescriptor descriptor(PublicKeyCredentialDescriptor descriptor) {
        Set<AuthenticatorTransport> transports = descriptor.getTransports() == null ? null
                : descriptor.getTransports().stream()
                        .map(transport -> AuthenticatorTransport.valueOf(transport.getValue()))
                        .collect(Collectors.toSet());
        return PublicKeyCredentialDescriptor.builder()
                .type(PublicKeyCredentialType.valueOf(descriptor.getType().getValue()))
                .id(descriptor.getId())
                .transports(transports)
                .build();
    }

    private AuthenticatorSelectionCriteria selection(PasskeyAuthenticatorSelectionState state) {
        if (state == null) {
            return null;
        }
        return AuthenticatorSelectionCriteria.builder()
                .authenticatorAttachment(state.attachment() == null ? null
                        : AuthenticatorAttachment.valueOf(state.attachment()))
                .residentKey(state.residentKey() == null ? null : ResidentKeyRequirement.valueOf(state.residentKey()))
                .userVerification(userVerification(state.userVerification()))
                .build();
    }

    private UserVerificationRequirement userVerification(String value) {
        if (value == null) {
            return null;
        }
        return switch (value) {
            case "required" -> UserVerificationRequirement.REQUIRED;
            case "preferred" -> UserVerificationRequirement.PREFERRED;
            case "discouraged" -> UserVerificationRequirement.DISCOURAGED;
            default -> throw new IllegalArgumentException("Unsupported passkey user verification requirement");
        };
    }
}
