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
package io.contexa.contexaiam.admin.promptquality.inspection;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.TextNode;
import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacommon.security.baseline.BaselineVector;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.baseline.store.BaselineDataStore;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptBundles;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageRepository;
import io.contexa.contexacore.verification.replay.SealedDecisionReplayService;
import io.contexa.contexaiam.admin.promptquality.inspection.SealedDecisionReplays.Baselines;
import io.contexa.contexaiam.admin.promptquality.inspection.SealedDecisionReplays.ReplayRequest;
import io.contexa.contexaiam.admin.promptquality.inspection.SealedDecisionReplays.Replayed;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/** docs/agent OC-5: an operator replays a sealed decision with a chosen bundle through the admin API. */
class SealedDecisionReplaysTest {

    private static final String BUNDLE = SecurityDecisionPromptBundles.V21.version();
    private static final ObjectMapper JSON = new ObjectMapper().findAndRegisterModules();

    private final SealedEvidencePackageRepository packages = mock(SealedEvidencePackageRepository.class);
    private final SealedDecisionReplayService service = mock(SealedDecisionReplayService.class);
    private final BaselineDataStore baselines = mock(BaselineDataStore.class);
    private final CentralAuditFacade audit = mock(CentralAuditFacade.class);
    private final SealedDecisionReplays replays = new SealedDecisionReplays(packages, () -> service, baselines, audit,
            JSON);
    private final Authentication operator = new UsernamePasswordAuthenticationToken("admin-1", null, List.of());
    private final SealedEvidencePackage sealed = sealed();

    @Test
    void aSealedDecisionIsReplayedWithTheGivenBaselinesAndTheReplayIsAudited() throws Exception {
        when(packages.findByCorrelationId("req-1")).thenReturn(Optional.of(sealed));
        when(service.replay(eq(sealed), any(), any(), eq(BUNDLE), eq(SealedDecisionReplays.TIMEOUT), eq(List.of("m2"))))
                .thenReturn(result("ALLOW", null));
        BaselineVector given = new BaselineVector();
        given.setUserId("template-user");

        Replayed replayed = replays.replayRequest("admin-1", "req-1", new ReplayRequest(BUNDLE, List.of(" m2 ", ""),
                TextNode.valueOf(JSON.writeValueAsString(given)), null)).orElseThrow();

        assertThat(replayed.baselines()).isEqualTo(Baselines.GIVEN);
        assertThat(replayed.result().action()).isEqualTo("ALLOW");
        ArgumentCaptor<BaselineVector> user = ArgumentCaptor.forClass(BaselineVector.class);
        verify(service).replay(eq(sealed), user.capture(), any(), eq(BUNDLE), any(), any());
        assertThat(user.getValue().getUserId()).as("read under the decision's user").isEqualTo("alice");
        verifyNoInteractions(baselines);
        ArgumentCaptor<AuditRecord> audited = ArgumentCaptor.forClass(AuditRecord.class);
        verify(audit).recordAsync(audited.capture());
        assertThat(audited.getValue().getEventCategory()).isEqualTo(AuditEventCategory.SEALED_DECISION_REPLAYED);
        assertThat(audited.getValue().getPrincipalName()).isEqualTo("admin-1");
        assertThat(audited.getValue().getDetails()).containsEntry("bundleVersion", BUNDLE)
                .containsEntry("baselines", "GIVEN").containsEntry("packageId", "pkg-1");
    }

    @Test
    void withoutBaselinesTheOnesKeptNowAreReadAndLeftAsTheyAre() {
        when(packages.findByPackageId("pkg-1")).thenReturn(Optional.of(sealed));
        BaselineVector kept = new BaselineVector();
        kept.setUserId("tenant-a::alice");
        BaselineVector organization = new BaselineVector();
        when(baselines.getUserBaseline("tenant-a::alice")).thenReturn(kept);
        when(baselines.getOrganizationBaseline("org-a")).thenReturn(organization);
        when(service.replay(any(), any(), any(), any(), any(), any())).thenReturn(result(null, "TimeoutException"));

        Replayed replayed = replays.replayPackage("admin-1", "pkg-1", new ReplayRequest(BUNDLE, null, null, null))
                .orElseThrow();

        assertThat(replayed.baselines()).isEqualTo(Baselines.CURRENT);
        ArgumentCaptor<BaselineVector> user = ArgumentCaptor.forClass(BaselineVector.class);
        ArgumentCaptor<BaselineVector> org = ArgumentCaptor.forClass(BaselineVector.class);
        verify(service).replay(eq(sealed), user.capture(), org.capture(), eq(BUNDLE), any(), eq(List.of()));
        assertThat(user.getValue().getUserId()).isEqualTo("alice");
        assertThat(kept.getUserId()).as("the kept baseline is not changed").isEqualTo("tenant-a::alice");
        assertThat(org.getValue()).isNotNull();
        ArgumentCaptor<AuditRecord> audited = ArgumentCaptor.forClass(AuditRecord.class);
        verify(audit).recordAsync(audited.capture());
        assertThat(audited.getValue().getOutcome()).isEqualTo("FAILED");
    }

    @Test
    void theApiAnswersWithTheStatusOfEachOutcome() {
        SealedDecisionReplayApiController api = new SealedDecisionReplayApiController(replays);
        when(packages.findByCorrelationId("req-1")).thenReturn(Optional.of(sealed));
        when(service.replay(any(), any(), any(), any(), any(), any())).thenReturn(result("BLOCK", null));

        assertThat(api.bundles()).contains(BUNDLE);
        assertThat(api.replayRequest("req-1", new ReplayRequest(BUNDLE, null, null, null), operator).getStatusCode())
                .isEqualTo(HttpStatus.OK);
        assertThat(api.replayRequest("nope", new ReplayRequest(BUNDLE, null, null, null), operator).getStatusCode())
                .isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(api.replayRequest("req-1", new ReplayRequest("v0-unknown", null, null, null), operator)
                .getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(api.replayRequest("req-1", null, operator).getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(api.replayRequest("req-1", new ReplayRequest(BUNDLE, List.of("a", "b", "c", "d"), null, null),
                operator).getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        SealedDecisionReplayApiController withoutPipeline = new SealedDecisionReplayApiController(
                new SealedDecisionReplays(packages, () -> null, baselines, audit, JSON));
        assertThat(withoutPipeline.replayRequest("req-1", new ReplayRequest(BUNDLE, null, null, null), operator)
                .getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        assertThat(SealedDecisionReplayApiController.class.getAnnotation(PreAuthorize.class).value())
                .isEqualTo("hasAuthority('ROLE_ADMIN')");
        assertThat(SealedDecisionReplayApiController.class.getAnnotation(RequestMapping.class).value())
                .containsExactly("/contexa/admin/api/sealed-decisions");
    }

    @Test
    void aBaselineThatIsNotOneIsRefused() {
        when(packages.findByCorrelationId("req-1")).thenReturn(Optional.of(sealed));

        assertThatThrownBy(() -> replays.replayRequest("admin-1", "req-1", new ReplayRequest(BUNDLE, null,
                TextNode.valueOf("{not json"), null))).isInstanceOf(IllegalArgumentException.class);
    }

    private static SealedEvidencePackage sealed() {
        SealedEvidencePackage sealed = new SealedEvidencePackage();
        sealed.setPackageId("pkg-1");
        sealed.setCorrelationId("req-1");
        sealed.setTenantId("tenant-a");
        sealed.setUserId("alice");
        sealed.setCanonicalContextJson("{\"actor\":{\"userId\":\"alice\",\"organizationId\":\"org-a\"}}");
        return sealed;
    }

    private static SealedDecisionReplayService.Result result(String action, String failure) {
        return new SealedDecisionReplayService.Result("req-1", "replay-1", "pkg-1", BUNDLE, action, "reason",
                List.of(), null, null, Map.of(), 12L, failure, List.of());
    }
}
