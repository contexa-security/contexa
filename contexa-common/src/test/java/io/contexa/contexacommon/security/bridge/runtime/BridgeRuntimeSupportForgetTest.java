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
package io.contexa.contexacommon.security.bridge.runtime;

import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.sync.BridgeUserMirrorSyncResult;
import io.contexa.contexacommon.security.bridge.sync.BridgeUserMirrorSyncService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** docs/agent/bridge-v2-B5-2-B5-3-설계안.md 2, ContexaUsers.delete: the request path lets go of a deleted user's copy. */
@DisplayName("bridge v2 사용자 삭제: 요청 경로가 기억한 사본을 아이디 규칙대로 비운다")
class BridgeRuntimeSupportForgetTest {

    private static final BridgeUserMirrorSyncResult KIM_COPY =
            new BridgeUserMirrorSyncResult(7L, "brg_kim01", "kim01", "key-kim01", true, true, true, false);

    private final BridgeUserMirrorSyncService sync = mock(BridgeUserMirrorSyncService.class);
    private final BridgeRuntimeSupport support = new BridgeRuntimeSupport(new BridgeProperties(), sync);

    @AfterEach
    void close() {
        support.destroy();
    }

    @Test
    @DisplayName("아이디 규칙이 같은 사람으로 보는 철자로 지워도 그 사람의 기억이 비고, 다른 사람의 기억은 남는다")
    void theDeletedUsersCopyIsForgottenUnderAnySpellingOfTheRule() {
        when(sync.sync(any(), any(), any(), anyBoolean())).thenReturn(KIM_COPY);
        support.setUserKey(id -> id.toLowerCase(Locale.ROOT));
        support.synchronizeUser(null, stamp("kim01"), null, request(), true);
        support.synchronizeUser(null, stamp("lee02"), null, request(), true);

        support.forget(" KIM01 ");

        assertThat(support.synchronizeUser(null, stamp("kim01"), null, request(), false))
                .as("nothing kept: the request goes on without the copy and asks the database again").isNull();
        assertThat(support.synchronizeUser(null, stamp("lee02"), null, request(), false)).isNotNull();
    }

    @Test
    @DisplayName("빈 아이디로는 아무 기억도 지우지 않는다")
    void aBlankUserIdForgetsNothing() {
        when(sync.sync(any(), any(), any(), anyBoolean())).thenReturn(KIM_COPY);
        support.synchronizeUser(null, stamp("kim01"), null, request(), true);

        support.forget(" ");

        assertThat(support.synchronizeUser(null, stamp("kim01"), null, request(), false)).isNotNull();
    }

    private static AuthenticationStamp stamp(String subject) {
        return new AuthenticationStamp(subject, subject, "USER", true, "PASSWORD", "REQUEST_ATTRIBUTE", null, null,
                Instant.parse("2026-11-26T01:00:00Z"), null, List.of(), Map.of());
    }

    private static RequestContextSnapshot request() {
        return new RequestContextSnapshot("/legacy/page", "GET", "203.0.113.5", "ua", null, "r-1", "/legacy/page",
                null, false, Instant.now());
    }
}
