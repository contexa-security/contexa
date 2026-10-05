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

import io.contexa.contexacore.autonomous.service.UserStatePurgeContributor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.web.webauthn.api.CredentialRecord;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;

/**
 * Deletes the passkeys of a deleted account. Spring Security resolves a passkey sign-in to the user name stored in
 * its user entity, so a passkey left behind would sign in to any later account created with the same name.
 */
public class PasskeyUserStatePurgeContributor implements UserStatePurgeContributor {

    private final ObjectProvider<PublicKeyCredentialUserEntityRepository> userEntities;
    private final ObjectProvider<UserCredentialRepository> userCredentials;

    public PasskeyUserStatePurgeContributor(
            ObjectProvider<PublicKeyCredentialUserEntityRepository> userEntities,
            ObjectProvider<UserCredentialRepository> userCredentials) {
        this.userEntities = userEntities;
        this.userCredentials = userCredentials;
    }

    @Override
    public String name() {
        return "passkeys";
    }

    @Override
    public void purge(String userId) {
        PublicKeyCredentialUserEntityRepository entities = userEntities.getIfAvailable();
        UserCredentialRepository credentials = userCredentials.getIfAvailable();
        if (entities == null || credentials == null) {
            return;
        }
        PublicKeyCredentialUserEntity entity = entities.findByUsername(userId);
        if (entity == null) {
            return;
        }
        for (CredentialRecord credential : credentials.findByUserId(entity.getId())) {
            credentials.delete(credential.getCredentialId());
        }
        entities.delete(entity.getId());
    }
}
