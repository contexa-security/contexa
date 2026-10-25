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
package io.contexa.contexaiam.admin.web.agent.controller;

import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacore.autonomous.agent.InMemoryDelegationRegistry;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexaiam.admin.web.agent.controller.AgentDelegationViews.DelegationBody;
import io.contexa.contexaiam.admin.web.agent.controller.AgentDelegationViews.DelegationView;
import io.contexa.contexaiam.admin.web.agent.controller.AgentDelegationViews.RevokeBody;
import io.contexa.contexaiam.admin.web.agent.service.AgentDelegationService;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * docs/agent OC-1: a person records, lists and revokes their own delegations; an administrator or an integration
 * records them for people as their records state them; an agent never records one; every change is audited.
 */
class AgentDelegationApiControllerTest {

    private static final Instant NOW = Instant.parse("2026-10-23T05:00:00Z");

    private final InMemoryDelegationRegistry registry = new InMemoryDelegationRegistry(Duration.ofDays(30),
            Clock.fixed(NOW, ZoneOffset.UTC));
    private final CentralAuditFacade audit = mock(CentralAuditFacade.class);
    private final AgentDelegationService service = new AgentDelegationService(registry,
            (tenantId, client) -> "agent-self".equals(client) ? Optional.of("agent-self") : Optional.empty(), audit);
    private final AgentDelegationApiController api = new AgentDelegationApiController(service,
            Clock.fixed(NOW, ZoneOffset.UTC));
    private final AgentDelegationAdminApiController admin = new AgentDelegationAdminApiController(service,
            Clock.fixed(NOW, ZoneOffset.UTC));

    @Test
    void aPersonRecordsListsAndRevokesTheirOwnDelegation() {
        Authentication alice = person("alice");

        ResponseEntity<?> recorded = api.record(body("someone-else", "agent-7"), alice, new MockHttpServletRequest());

        assertThat(recorded.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        DelegationView view = (DelegationView) recorded.getBody();
        // The delegator and the writer are the signed-in person, whatever the body says.
        assertThat(view.delegatorId()).isEqualTo("alice");
        assertThat(view.recordedBy()).isEqualTo("alice");
        assertThat(view.state()).isEqualTo("VALID");
        assertThat(view.allowedOperations()).containsExactly("READ");
        assertThat((List<?>) api.own(alice, new MockHttpServletRequest()).getBody()).hasSize(1);
        assertThat(api.revoke(view.delegationId(), new RevokeBody("done"), person("bob"),
                new MockHttpServletRequest()).getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);

        ResponseEntity<?> revoked = api.revoke(view.delegationId(), new RevokeBody("done"), alice,
                new MockHttpServletRequest());

        assertThat(((DelegationView) revoked.getBody()).state()).isEqualTo("REVOKED");
        ArgumentCaptor<AuditRecord> records = ArgumentCaptor.forClass(AuditRecord.class);
        verify(audit, times(2)).recordAsync(records.capture());
        assertThat(records.getAllValues()).extracting(AuditRecord::getEventCategory).containsExactly(
                AuditEventCategory.AGENT_DELEGATION_RECORDED, AuditEventCategory.AGENT_DELEGATION_REVOKED);
        assertThat(records.getAllValues().get(0).getPrincipalName()).isEqualTo("alice");
        assertThat(records.getAllValues().get(0).getResourceIdentifier()).isEqualTo("agent-7");
    }

    @Test
    void anAgentCannotRecordOrRevokeADelegation() {
        Authentication actingForAPerson = jwt("alice", Map.of("act", Map.of("sub", "agent-client"),
                "client_id", "agent-client"));
        Authentication ownToken = jwt("agent-client", Map.of("client_id", "agent-client"));
        Authentication ownAccount = person("agent-self");

        for (Authentication agent : List.of(actingForAPerson, ownToken, ownAccount)) {
            assertThat(api.record(body(null, "agent-7"), agent, new MockHttpServletRequest()).getStatusCode())
                    .isEqualTo(HttpStatus.FORBIDDEN);
        }
        assertThat(registry.list(null, null, null, 10)).isEmpty();
        verify(audit, never()).recordAsync(any());
        // A person's token issued to an ordinary client may record.
        assertThat(api.record(body(null, "agent-7"), jwt("alice", Map.of("client_id", "portal")),
                new MockHttpServletRequest()).getStatusCode()).isEqualTo(HttpStatus.CREATED);
    }

    @Test
    void anIncompleteDelegationIsRefused() {
        DelegationBody noEnd = new DelegationBody(null, null, "agent-7", null, null, null, null, null, null, null,
                null, null, null, null, null);

        assertThat(api.record(noEnd, person("alice"), new MockHttpServletRequest()).getStatusCode())
                .isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(api.record(null, person("alice"), new MockHttpServletRequest()).getStatusCode())
                .isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void anAdministratorRecordsForAPersonAsTheRecordsStateItAndRevokesWithAReason() {
        DelegationBody imported = new DelegationBody("t-1", "alice", "agent-7", "OBJ-1", "REPORTING",
                "Weekly report", List.of("READ"), List.of("HX-310"), false, null, null, NOW.minusSeconds(3600),
                NOW.plusSeconds(3600), "hr-system", NOW.minusSeconds(7200));

        DelegationView view = (DelegationView) admin.record(imported, person("admin-1")).getBody();

        assertThat(view.delegatorId()).isEqualTo("alice");
        assertThat(view.recordedBy()).isEqualTo("hr-system");
        assertThat(view.recordedAt()).isEqualTo(NOW.minusSeconds(7200));
        assertThat(admin.list("t-1", null, "agent-7", 50)).extracting(DelegationView::delegationId)
                .containsExactly(view.delegationId());
        assertThat(admin.revoke(view.delegationId(), new RevokeBody(" "), person("admin-1")).getStatusCode())
                .isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(((DelegationView) admin.revoke(view.delegationId(), new RevokeBody("hijacked"),
                person("admin-1")).getBody()).revokedBy()).isEqualTo("admin-1");
    }

    /** RL-6: a delegation states its quantity limits in the body, and the view returns them. */
    @Test
    void aDelegationBodyMayStateQuantityLimitsAndTheViewReturnsThem() {
        DelegationBody limited = new DelegationBody("t-1", "alice", "agent-7", "OBJ-1", "REPORTING", "Weekly report",
                List.of("READ", "EXPORT"), List.of("HX-310"), false, null, null, NOW.minusSeconds(3600),
                NOW.plusSeconds(3600), "hr-system", NOW.minusSeconds(7200), 40, 1200);

        DelegationView view = (DelegationView) admin.record(limited, person("admin-1")).getBody();

        assertThat(view.maxItemsPerRequest()).isEqualTo(40);
        assertThat(view.maxItemsTotal()).isEqualTo(1200);
        // A limit below one is refused like any other incomplete delegation.
        assertThat(admin.record(new DelegationBody("t-1", "alice", "agent-8", null, "REPORTING", null, List.of("READ"),
                List.of("HX-310"), false, null, null, NOW.minusSeconds(60), NOW.plusSeconds(3600), null, null, 0, null),
                person("admin-1")).getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void thePersonsApiNeedsASignInAndTheAdminApiAnAdministrator() {
        assertThat(AgentDelegationApiController.class.getAnnotation(PreAuthorize.class).value())
                .isEqualTo("isAuthenticated()");
        assertThat(AgentDelegationAdminApiController.class.getAnnotation(PreAuthorize.class).value())
                .isEqualTo("hasRole('ADMIN')");
    }

    private static DelegationBody body(String delegator, String agent) {
        return new DelegationBody("ignored-tenant", delegator, agent, null, "REPORTING", "Weekly HX-310 report",
                List.of("read"), List.of("HX-310"), false, null, null, NOW.minusSeconds(60), NOW.plusSeconds(3600),
                "forged-writer", NOW.minus(Duration.ofDays(400)));
    }

    private static Authentication person(String name) {
        return new UsernamePasswordAuthenticationToken(name, null, List.of());
    }

    private static Authentication jwt(String subject, Map<String, Object> claims) {
        Jwt.Builder builder = Jwt.withTokenValue("token").header("alg", "none").subject(subject)
                .issuedAt(NOW.minusSeconds(60)).expiresAt(NOW.plusSeconds(600));
        claims.forEach(builder::claim);
        return new JwtAuthenticationToken(builder.build(), List.of(), subject);
    }
}
