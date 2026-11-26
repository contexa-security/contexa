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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.CredentialRecord;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** docs/agent/bridge-v2-B5-2-B5-3-설계안.md 3, decision Q4: a person's passkeys when two of its copies become one. */
@DisplayName("bridge v2 사본 합치기: 패스키는 사용자 몰래 지우지 않고 남는 사본의 이름으로 옮긴다")
class PasskeyUserCopyMergeContributorTest {

    private static final Bytes KEPT_ID = Bytes.random();
    private static final Bytes MERGED_ID = Bytes.random();

    private final PublicKeyCredentialUserEntityRepository entities = mock(PublicKeyCredentialUserEntityRepository.class);
    private final UserCredentialRepository credentials = mock(UserCredentialRepository.class);
    private final PasskeyUserCopyMergeContributor contributor =
            new PasskeyUserCopyMergeContributor(() -> entities, () -> credentials);

    @Test
    @DisplayName("두 사본이 모두 패스키를 가지면 합치기를 거부한다")
    void bothCopiesHoldingPasskeysRefuseTheMerge() {
        entity("brg_kept", KEPT_ID, true);
        entity("brg_merged", MERGED_ID, true);

        assertThat(contributor.refusal("brg_kept", "brg_merged")).isNotNull();
    }

    @Test
    @DisplayName("한쪽만 패스키를 가지면 거부하지 않는다")
    void oneCopyHoldingPasskeysLetsTheMergeGoOn() {
        entity("brg_kept", KEPT_ID, false);
        entity("brg_merged", MERGED_ID, true);

        assertThat(contributor.refusal("brg_kept", "brg_merged")).isNull();
    }

    @Test
    @DisplayName("합친 사본의 패스키 엔티티는 같은 식별값으로 남는 사본의 이름을 받고, 남는 사본의 빈 엔티티는 지워진다")
    void theMergedCopysPasskeysTakeTheKeptCopysNameUnderTheSameHandle() {
        entity("brg_kept", KEPT_ID, false);
        entity("brg_merged", MERGED_ID, true);

        contributor.merge("brg_kept", "brg_merged");

        verify(entities).delete(KEPT_ID);
        ArgumentCaptor<PublicKeyCredentialUserEntity> saved = ArgumentCaptor.forClass(PublicKeyCredentialUserEntity.class);
        verify(entities).save(saved.capture());
        assertThat(saved.getValue().getId()).isEqualTo(MERGED_ID);
        assertThat(saved.getValue().getName()).isEqualTo("brg_kept");
        verify(credentials, never()).delete(any());
    }

    @Test
    @DisplayName("합친 사본에 패스키 없는 빈 엔티티만 있으면 그것을 지우고 남는 사본은 그대로 둔다")
    void anEmptyEntityOfTheMergedCopyGoes() {
        entity("brg_kept", KEPT_ID, true);
        entity("brg_merged", MERGED_ID, false);

        contributor.merge("brg_kept", "brg_merged");

        verify(entities).delete(MERGED_ID);
        verify(entities, never()).delete(KEPT_ID);
        verify(entities, never()).save(any());
    }

    private void entity(String name, Bytes id, boolean withPasskey) {
        when(entities.findByUsername(name)).thenReturn(ImmutablePublicKeyCredentialUserEntity.builder()
                .name(name).id(id).displayName("kim01").build());
        when(credentials.findByUserId(id)).thenReturn(withPasskey ? List.of(mock(CredentialRecord.class)) : List.of());
    }
}
