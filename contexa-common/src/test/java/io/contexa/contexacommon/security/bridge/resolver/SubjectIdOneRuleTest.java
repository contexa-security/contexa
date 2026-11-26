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
package io.contexa.contexacommon.security.bridge.resolver;

import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.ContexaIdentity;
import io.contexa.contexacommon.security.bridge.authentication.BridgeAuthenticationToken;
import io.contexa.contexacommon.security.bridge.authentication.BridgePrincipal;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;

import java.security.Principal;
import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R-10 of docs/agent/운영모드-정상화-구현계획.md (analysis L-05): one rule decides the subject of an authentication, the
 * name Zero Trust keys its decisions by. The bridge's stamp, and so the copy of the user, used a principal or details key
 * before the name, and one person was two subjects when the two differed.
 */
@DisplayName("주체 ID 결정기는 하나다(R-10, L-05)")
class SubjectIdOneRuleTest {

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("보안 문맥의 도장 주체는 판정 키와 같은 getName()이다(사용자 ID 키가 달라도)")
    void theStampOfTheSecurityContextIsKeyedByTheName() {
        UsernamePasswordAuthenticationToken authentication = UsernamePasswordAuthenticationToken.authenticated(
                new StaffPrincipal("alice", "u-1"), null, AuthorityUtils.createAuthorityList("ROLE_USER"));
        authentication.setDetails(Map.of("userId", "u-2"));
        SecurityContextHolder.getContext().setAuthentication(authentication);

        AuthenticationStamp stamp = new SecurityContextAuthenticationStampResolver()
                .resolve(null, requestContext(), new BridgeProperties()).orElseThrow();

        assertThat(stamp.principalId()).isEqualTo("alice").isEqualTo(ContexaIdentity.subjectId(authentication));
    }

    @Test
    @DisplayName("Contexa가 만든 bridge 인증은 그것을 만든 앱 주체로 다시 읽힌다")
    void contexasOwnBridgeAuthenticationIsReadAsTheSubjectItWasMadeFrom() {
        BridgePrincipal principal = new BridgePrincipal("SUBJECT|org|alice", "alice", "Alice", null, null, null, null,
                null, 7L, "SUBJECT|org|alice", true, true);
        SecurityContextHolder.getContext().setAuthentication(new BridgeAuthenticationToken(principal,
                AuthorityUtils.createAuthorityList("ROLE_USER"), null));

        AuthenticationStamp stamp = new SecurityContextAuthenticationStampResolver()
                .resolve(null, requestContext(), new BridgeProperties()).orElseThrow();

        assertThat(stamp.principalId()).isEqualTo("alice");
    }

    private static RequestContextSnapshot requestContext() {
        return new RequestContextSnapshot("/orders", "GET", "10.0.0.10", "JUnit", "session-1", "request-1",
                "/orders", null, false, Instant.now());
    }

    /** A principal whose user ID differs from the name it signs in with. */
    public record StaffPrincipal(String username, String userId) implements Principal {
        @Override
        public String getName() {
            return username;
        }
    }
}
