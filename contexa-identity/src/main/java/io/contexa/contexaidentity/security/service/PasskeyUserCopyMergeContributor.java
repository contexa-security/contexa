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

import io.contexa.contexacommon.security.bridge.sync.UserCopyMergeContributor;
import org.springframework.lang.Nullable;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;

import java.util.function.Supplier;

/**
 * bridge v2 B5-3 (docs/agent/bridge-v2-B5-2-B5-3-설계안.md 3, decision Q4): the passkeys of two copies of one person when the
 * synchronisation merges them. A passkey belongs to the user entity named after its copy. The merged copy's passkeys go to
 * the kept copy by the name of their user entity, which leaves the user handle the authenticator holds and the credentials
 * as they are. When both copies hold passkeys, Contexa does not drop one the user registered: the copies stay apart until
 * one copy's passkeys are gone.
 */
public class PasskeyUserCopyMergeContributor implements UserCopyMergeContributor {

    private final Supplier<PublicKeyCredentialUserEntityRepository> userEntities;
    private final Supplier<UserCredentialRepository> userCredentials;

    /** Asked at the time of a merge, and either may answer nothing. */
    public PasskeyUserCopyMergeContributor(
            Supplier<PublicKeyCredentialUserEntityRepository> userEntities,
            Supplier<UserCredentialRepository> userCredentials) {
        this.userEntities = userEntities;
        this.userCredentials = userCredentials;
    }

    @Override
    @Nullable
    public String refusal(String keptUsername, String mergedUsername) {
        PublicKeyCredentialUserEntityRepository entities = userEntities.get();
        UserCredentialRepository credentials = userCredentials.get();
        if (entities == null || credentials == null) {
            return null;
        }
        return holdsPasskeys(entities.findByUsername(keptUsername), credentials)
                && holdsPasskeys(entities.findByUsername(mergedUsername), credentials)
                ? "both copies hold passkeys" : null;
    }

    @Override
    public void merge(String keptUsername, String mergedUsername) {
        PublicKeyCredentialUserEntityRepository entities = userEntities.get();
        UserCredentialRepository credentials = userCredentials.get();
        if (entities == null || credentials == null) {
            return;
        }
        PublicKeyCredentialUserEntity merged = entities.findByUsername(mergedUsername);
        if (merged == null) {
            return;
        }
        if (!holdsPasskeys(merged, credentials)) {
            entities.delete(merged.getId());
            return;
        }
        PublicKeyCredentialUserEntity kept = entities.findByUsername(keptUsername);
        if (kept != null) {
            entities.delete(kept.getId());
        }
        entities.save(ImmutablePublicKeyCredentialUserEntity.builder()
                .name(keptUsername)
                .id(merged.getId())
                .displayName(merged.getDisplayName())
                .build());
    }

    private static boolean holdsPasskeys(@Nullable PublicKeyCredentialUserEntity entity,
                                         UserCredentialRepository credentials) {
        return entity != null && !credentials.findByUserId(entity.getId()).isEmpty();
    }
}
