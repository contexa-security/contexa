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

import io.contexa.contexacore.autonomous.agent.AgentLearningControl;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.baseline.store.InMemoryBaselineDataStore;
import io.contexa.contexacore.autonomous.context.support.PastRecordQuery;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacommon.security.baseline.BaselineVector;
import io.contexa.contexaiam.admin.web.agent.controller.LearningActionRequest;
import io.contexa.contexaiam.admin.web.agent.controller.LearningActionResponse;
import io.contexa.contexaiam.admin.web.agent.service.AgentLearningAdminService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.RequestMapping;

import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** docs/agent A3-8: the admin API quarantines, releases and removes what an agent learned, and reads the state. */
class AgentLearningApiControllerTest {

    private final InMemorySecurityContextDataStore contextStore = new InMemorySecurityContextDataStore();
    private final InMemoryBaselineDataStore baselineStore = new InMemoryBaselineDataStore(Duration.ofDays(30));
    private final PastRecordQuery records = mock(PastRecordQuery.class);
    private final CentralAuditFacade audit = mock(CentralAuditFacade.class);
    private final AgentLearningApiController controller = new AgentLearningApiController(
            new AgentLearningAdminService(new AgentLearningControl(contextStore, baselineStore, () -> records), audit));

    @BeforeEach
    void signIn() {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("admin-1", null, List.of()));
    }

    @AfterEach
    void signOut() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void anAgentsLearningIsQuarantinedReleasedAndRemovedWithEveryActionAudited() {
        when(records.quarantineAgentRecords("agt/1", null)).thenReturn(3);
        when(records.removeAgentRecords("agt/1", null)).thenReturn(3);
        baselineStore.saveUserBaseline("alice::agent::agt/1", BaselineVector.builder().userId("alice").build());

        ResponseEntity<LearningActionResponse> quarantined = controller.act(
                new LearningActionRequest("agt/1", null, "QUARANTINE", "prompt injection learned"));

        assertThat(quarantined.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(quarantined.getBody().success()).isTrue();
        assertThat(quarantined.getBody().records()).isEqualTo(3);
        assertThat(controller.state("agt/1", null).getBody().quarantined()).isTrue();

        controller.act(new LearningActionRequest("agt/1", null, "release", "reviewed"));
        assertThat(controller.state("agt/1", null).getBody().quarantined()).isFalse();

        ResponseEntity<LearningActionResponse> removed = controller.act(
                new LearningActionRequest("agt/1", null, "remove", "decommissioned"));

        assertThat(removed.getBody().baselines()).isEqualTo(1);
        assertThat(baselineStore.getUserBaseline("alice::agent::agt/1")).isNull();
        verify(audit, times(3)).recordAsync(any());
    }

    @Test
    void aRequestWithoutAnAgentAnActionOrAReasonIsRefused() {
        assertThat(controller.act(null).getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(controller.act(new LearningActionRequest(" ", null, "QUARANTINE", "why")).getStatusCode())
                .isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(controller.act(new LearningActionRequest("agt-1", null, "forget", "why")).getStatusCode())
                .isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(controller.act(new LearningActionRequest("agt-1", null, "QUARANTINE", null)).getStatusCode())
                .isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(contextStore.learningQuarantineScopes()).isEmpty();
        verify(audit, never()).recordAsync(any());
    }

    @Test
    void withoutTheAutonomousSecurityPlaneEveryActionIsRefused() {
        AgentLearningApiController off = new AgentLearningApiController(new AgentLearningAdminService(null, null));

        assertThat(off.act(new LearningActionRequest("agt-1", null, "QUARANTINE", "why")).getStatusCode())
                .isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        assertThat(off.state("agt-1", null).getBody().quarantined()).isFalse();
    }

    @Test
    void onlyAdministratorsReachTheApi() {
        assertThat(AgentLearningApiController.class.getAnnotation(PreAuthorize.class).value())
                .isEqualTo("hasAuthority('ROLE_ADMIN')");
        assertThat(AgentLearningApiController.class.getAnnotation(RequestMapping.class).value())
                .containsExactly("/contexa/admin/api/agents/learning");
    }
}
