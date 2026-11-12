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
package io.contexa.contexacommon.bridge.resolver;

import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.BridgeSemanticBoundaryPolicy;
import io.contexa.contexacommon.security.bridge.resolver.AgentAccountDelegationStampResolver;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import io.contexa.contexacommon.security.subject.AgentClientDirectory;
import io.contexa.contexacommon.security.subject.AgentClientStatusUnavailableException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A1-13: an approved agent signed in with its own account (a session login) is that agent acting on its own; a person's
 * account is not looked up beyond the one directory question and yields no stamp.
 */
@ExtendWith(OutputCaptureExtension.class)
class AgentAccountDelegationStampResolverTest {

    private final List<String> lookups = new ArrayList<>();
    private final AgentAccountDelegationStampResolver resolver = new AgentAccountDelegationStampResolver(
            new AgentClientDirectory() {
                @Override
                public Optional<String> activeAgentForClient(String tenantId, String clientId) {
                    lookups.add(tenantId + "|" + clientId);
                    return "report-bot".equals(clientId) ? Optional.of("report-bot") : Optional.empty();
                }
            });

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void anApprovedAgentsSessionLoginIsThatAgentActingOnItsOwn() {
        signIn(UsernamePasswordAuthenticationToken.authenticated("report-bot", null, AuthorityUtils.NO_AUTHORITIES));

        DelegationStamp stamp = resolver.resolve(null, null, new BridgeProperties()).orElseThrow();

        assertThat(stamp.agentId()).isEqualTo("report-bot");
        assertThat(stamp.subjectId()).isEqualTo("report-bot");
        assertThat(stamp.delegated()).isFalse();
        assertThat(stamp.attributes())
                .containsEntry("delegationResolver", AgentAccountDelegationStampResolver.RESOLVER)
                .containsEntry("delegationEvidenceState", BridgeSemanticBoundaryPolicy.AGENT_REGISTRY_RECORD);
        assertThat(lookups).containsExactly("null|report-bot");
    }

    @Test
    void aPersonsAccountYieldsNoStamp() {
        signIn(UsernamePasswordAuthenticationToken.authenticated("alice", null, AuthorityUtils.NO_AUTHORITIES));

        assertThat(resolver.resolve(null, null, new BridgeProperties())).isEmpty();
    }

    @Test
    void anAnonymousOrMissingAuthenticationIsNotLookedUp() {
        assertThat(resolver.resolve(null, null, new BridgeProperties())).isEmpty();
        signIn(new AnonymousAuthenticationToken("key", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")));
        assertThat(resolver.resolve(null, null, new BridgeProperties())).isEmpty();
        assertThat(lookups).isEmpty();
    }

    @Test
    void aFailedLookupReadsThePrincipalAsAPerson() {
        AgentAccountDelegationStampResolver failing = new AgentAccountDelegationStampResolver((tenantId, clientId) -> {
            throw new IllegalStateException("registry down");
        });
        signIn(UsernamePasswordAuthenticationToken.authenticated("report-bot", null, AuthorityUtils.NO_AUTHORITIES));

        assertThat(failing.resolve(null, null, new BridgeProperties())).isEmpty();
    }

    /** Reading a request is not a decision: it asks the directory the question meant for requests, never the one that decides. */
    @Test
    void anAccountIsReadWithTheDirectorysAnswerForARequestAndNotItsAnswerForADecision() {
        AgentAccountDelegationStampResolver fromMemory = new AgentAccountDelegationStampResolver(new AgentClientDirectory() {
            @Override
            public Optional<String> activeAgentForClient(String tenantId, String clientId) {
                throw new AssertionError("a request does not wait for what decides");
            }

            @Override
            public Optional<String> requestPathActiveAgentForAccount(String tenantId, String accountName) {
                lookups.add(tenantId + "|" + accountName);
                return "report-bot".equals(accountName) ? Optional.of("report-bot") : Optional.empty();
            }
        });
        signIn(UsernamePasswordAuthenticationToken.authenticated("report-bot", null, AuthorityUtils.NO_AUTHORITIES));

        assertThat(fromMemory.resolve(null, null, new BridgeProperties()).orElseThrow().agentId()).isEqualTo("report-bot");
        signIn(UsernamePasswordAuthenticationToken.authenticated("alice", null, AuthorityUtils.NO_AUTHORITIES));
        assertThat(fromMemory.resolve(null, null, new BridgeProperties())).isEmpty();
        assertThat(lookups).containsExactly("null|report-bot", "null|alice");
    }

    /** A directory that cannot be read says so, and the account is read as a person, as a failed lookup always was. */
    @Test
    void anAccountTheDirectoryCannotBeAskedAboutIsReadAsAPerson() {
        AgentAccountDelegationStampResolver unreadable = new AgentAccountDelegationStampResolver(new AgentClientDirectory() {
            @Override
            public Optional<String> activeAgentForClient(String tenantId, String clientId) {
                return Optional.of("report-bot");
            }

            @Override
            public Optional<String> requestPathActiveAgentForAccount(String tenantId, String accountName) {
                throw new AgentClientStatusUnavailableException("The approved agents have not been read from the registry");
            }
        });
        signIn(UsernamePasswordAuthenticationToken.authenticated("report-bot", null, AuthorityUtils.NO_AUTHORITIES));

        assertThat(unreadable.resolve(null, null, new BridgeProperties())).isEmpty();
    }

    /** PR-200: a registry that stays away is told once and then counted, not once a request with its stack. */
    @Test
    void aRegistryThatStaysAwayIsToldOnceAndNotOnceARequest(CapturedOutput output) {
        AgentAccountDelegationStampResolver unreadable = new AgentAccountDelegationStampResolver(new AgentClientDirectory() {
            @Override
            public Optional<String> activeAgentForClient(String tenantId, String clientId) {
                return Optional.empty();
            }

            @Override
            public Optional<String> requestPathActiveAgentForAccount(String tenantId, String accountName) {
                throw new AgentClientStatusUnavailableException(
                        "The approved agents were last read from the registry too long ago");
            }
        });
        signIn(UsernamePasswordAuthenticationToken.authenticated("alice", null, AuthorityUtils.NO_AUTHORITIES));

        for (int request = 0; request < 200; request++) {
            assertThat(unreadable.resolve(null, null, new BridgeProperties())).isEmpty();
        }

        assertThat(StringUtils.countOccurrencesOf(output.getAll(), "could not be asked whether account"))
                .as("one line for the outage, the rest are counted").isEqualTo(1);
    }

    @Test
    void aTokensTenantScopesTheLookup() {
        Jwt jwt = Jwt.withTokenValue("token").header("alg", "RS256")
                .claims(claims -> claims.putAll(Map.of("sub", "report-bot", "tid", "acme")))
                .issuedAt(Instant.parse("2026-10-23T00:00:00Z")).expiresAt(Instant.parse("2026-10-23T01:00:00Z"))
                .build();
        signIn(new JwtAuthenticationToken(jwt, AuthorityUtils.NO_AUTHORITIES));

        assertThat(resolver.resolve(null, null, new BridgeProperties())).isPresent();
        assertThat(lookups).containsExactly("acme|report-bot");
    }

    private static void signIn(Authentication authentication) {
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}
