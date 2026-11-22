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
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacommon.security.baseline.BaselineVector;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.baseline.DecisionBaselines;
import io.contexa.contexacore.autonomous.baseline.store.BaselineDataStore;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptBundles;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDocument;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionCatalog;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.evidence.SealedDecisionBaselines;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageIntegrity;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageRepository;
import io.contexa.contexacore.verification.replay.SealedDecisionReplayService;
import io.contexa.contexaiam.admin.promptquality.inspection.SealedDecisionReplays.Baselines;
import io.contexa.contexaiam.admin.promptquality.inspection.SealedDecisionReplays.ReplayRequest;
import io.contexa.contexaiam.admin.promptquality.inspection.SealedDecisionReplays.Replayed;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.RequestMapping;

import java.time.ZoneId;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/** docs/agent OC-5: an operator replays a sealed decision with a chosen bundle through the admin API. */
class SealedDecisionReplaysTest {

    private static final String BUNDLE = SecurityDecisionPromptBundles.V1.version();
    private static final ObjectMapper JSON = new ObjectMapper().findAndRegisterModules();

    private final SealedEvidencePackageRepository packages = mock(SealedEvidencePackageRepository.class);
    private final SealedDecisionReplayService service = mock(SealedDecisionReplayService.class);
    private final BaselineDataStore baselines = mock(BaselineDataStore.class);
    private final CentralAuditFacade audit = mock(CentralAuditFacade.class);
    private final SealedEvidencePackageIntegrity integrity = new SealedEvidencePackageIntegrity();
    private final SealedDecisionReplays replays = new SealedDecisionReplays(packages, () -> service, baselines, audit,
            JSON, integrity);
    private final Authentication operator = new UsernamePasswordAuthenticationToken("admin-1", null, List.of());
    private final SealedEvidencePackage sealed = sealed();

    /**
     * The replays hand the service one request (quality plan 3.3). The stand-in reads it as the six values the stubs
     * and the verifications of the tests below name; what the request carries besides is read from the request itself.
     */
    @BeforeEach
    void theServiceReadsARequestByItsParts() {
        when(service.replay(any(SealedDecisionReplayService.Request.class))).thenAnswer(invocation -> {
            SealedDecisionReplayService.Request asked = invocation.getArgument(0);
            return service.replay(asked.sealed(), asked.personalBaseline(), asked.organizationBaseline(),
                    asked.bundleVersion(), asked.timeout(), asked.secondPassModels());
        });
    }

    /** Plan 6-2: without the version tables, v1.0, the one bundle the build runs, is the replay target. */
    @Test
    void withoutTheVersionTablesTheBundleOfTheBuildIsTheReplayTarget() {
        assertThat(replays.bundles()).containsExactly(SecurityDecisionPromptBundles.V1.version());
    }

    /**
     * Plan 3.8 (10), 3.9: the replay targets are the versions of the database that are not hidden, newest first; a
     * replay names a version, hidden or not, and draws it; a name the table does not have is refused before the replay.
     */
    @Test
    void theReplayTargetsAreTheShownVersionsOfTheDatabaseAndAReplayNamesOne() {
        PromptVersionCatalog catalog = mock(PromptVersionCatalog.class);
        List<PromptVersionCatalog.Entry> entries = List.of(entry(3, false), entry(2, true), entry(1, false));
        when(catalog.versions(any(), any())).thenReturn(entries);
        when(catalog.shown(any(), any())).thenCallRealMethod();
        when(catalog.find(any(), any(), any())).thenCallRealMethod();
        SealedDecisionReplays withVersions = new SealedDecisionReplays(packages, () -> service, baselines, audit, JSON,
                integrity, () -> catalog);
        when(packages.findByPackageId("pkg-1")).thenReturn(Optional.of(sealed));
        when(service.replay(any(), any(), any(), any(), any(), any())).thenReturn(result("ALLOW", null));

        assertThat(withVersions.bundles()).containsExactly("v3.0", "v1.0");
        assertThat(withVersions.replayPackage("admin-1", "pkg-1", new ReplayRequest("v2.0", null, null, null)))
                .isPresent();
        verify(service).replay(eq(sealed), any(), any(), eq("v2.0"), any(), any());
        assertThatThrownBy(() -> withVersions.replayPackage("admin-1", "pkg-1",
                new ReplayRequest("v9.0", null, null, null))).isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("v9.0");
    }

    private static PromptVersionCatalog.Entry entry(int number, boolean hidden) {
        return new PromptVersionCatalog.Entry("PLATFORM_GLOBAL", SecurityDecisionPromptDocument.PROMPT, number,
                "hash-" + number, number == 1 ? null : 1, number == 1 ? "CONTEXA" : "ORGANIZATION", hidden);
    }

    /**
     * Quality plan 3.2 (P24, P28): a given decision is drawn in the time zone it fixes, with the version of the scope
     * its request names; a version only another scope has is refused, and so is a time zone that is none. A package of
     * the store is replayed as before: a version of the platform scope, in the time zone of the server.
     */
    @Test
    void aGivenDecisionIsDrawnInItsTimeZoneWithTheVersionOfTheScopeAsked() {
        PromptVersionCatalog catalog = mock(PromptVersionCatalog.class);
        when(catalog.versions(eq("TENANT_A"), any())).thenReturn(List.of(new PromptVersionCatalog.Entry("TENANT_A",
                SecurityDecisionPromptDocument.PROMPT, 4, "hash-4", 1, "ORGANIZATION", false)));
        when(catalog.versions(eq(PromptVersionCatalog.PLATFORM_SCOPE), any())).thenReturn(List.of(entry(1, false)));
        when(catalog.find(any(), any(), any())).thenCallRealMethod();
        SealedDecisionReplays scoped = new SealedDecisionReplays(packages, () -> service, baselines, audit, JSON,
                integrity, () -> catalog);
        when(service.replay(any(), any(), any(), any(), any(), any())).thenReturn(result("ALLOW", null));

        scoped.replayGiven("admin-1", sealed(), "1", " Asia/Seoul ", new ReplayRequest("v4.0", null, null, null, true,
                "TENANT_A"));

        ArgumentCaptor<SealedDecisionReplayService.Request> asked =
                ArgumentCaptor.forClass(SealedDecisionReplayService.Request.class);
        verify(service).replay(asked.capture());
        assertThat(asked.getValue().bundleVersion()).isEqualTo("v4.0");
        assertThat(asked.getValue().scope()).isEqualTo("TENANT_A");
        assertThat(asked.getValue().timeZone()).isEqualTo(ZoneId.of("Asia/Seoul"));
        assertThatThrownBy(() -> scoped.replayGiven("admin-1", sealed(), "1", "UTC",
                new ReplayRequest("v4.0", null, null, null, true))).isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("v4.0");
        assertThatThrownBy(() -> scoped.replayGiven("admin-1", sealed(), "1", "Mars/Olympus",
                new ReplayRequest("v4.0", null, null, null, true, "TENANT_A")))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("Mars/Olympus");

        when(packages.findByPackageId("pkg-1")).thenReturn(Optional.of(sealed));
        assertThat(scoped.replayPackage("admin-1", "pkg-1", new ReplayRequest("v1.0", null, null, null))).isPresent();
        verify(service, times(2)).replay(asked.capture());
        assertThat(asked.getValue().scope()).isEqualTo(PromptVersionCatalog.PLATFORM_SCOPE);
        assertThat(asked.getValue().timeZone()).isNull();
    }

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

    /**
     * A package that sealed the baselines its decision read is drawn again with them; the baselines kept now, which
     * may have changed since the decision, are not read.
     */
    @Test
    void aPackageThatSealedItsBaselinesIsReplayedWithThem() {
        BaselineVector personal = BaselineVector.builder().userId("tenant-a::alice")
                .normalIpRanges(new String[]{"10.1.0.0/16"}).updateCount(42L).build();
        BaselineVector organization = BaselineVector.builder().userId("org:org-a")
                .normalOperatingSystems(new String[]{"WINDOWS"}).build();
        ObjectNode snapshot = JSON.createObjectNode().put("baselineEstablished", true);
        snapshot.set(SealedDecisionBaselines.KEY,
                SealedDecisionBaselines.write(new DecisionBaselines(personal, organization), JSON));
        sealed.setBaselineSnapshotJson(snapshot.toString());
        when(packages.findByPackageId("pkg-1")).thenReturn(Optional.of(sealed));
        when(service.replay(any(), any(), any(), any(), any(), any())).thenReturn(result("ALLOW", null));

        Replayed replayed = replays.replayPackage("admin-1", "pkg-1", new ReplayRequest(BUNDLE, null, null, null))
                .orElseThrow();

        assertThat(replayed.baselines()).isEqualTo(Baselines.SEALED);
        ArgumentCaptor<BaselineVector> user = ArgumentCaptor.forClass(BaselineVector.class);
        ArgumentCaptor<BaselineVector> org = ArgumentCaptor.forClass(BaselineVector.class);
        verify(service).replay(eq(sealed), user.capture(), org.capture(), eq(BUNDLE), any(), eq(List.of()));
        assertThat(user.getValue().getNormalIpRanges()).containsExactly("10.1.0.0/16");
        assertThat(user.getValue().getUpdateCount()).isEqualTo(42L);
        assertThat(user.getValue().getUserId()).as("read under the decision's user").isEqualTo("alice");
        assertThat(org.getValue().getNormalOperatingSystems()).containsExactly("WINDOWS");
        verifyNoInteractions(baselines);
        ArgumentCaptor<AuditRecord> audited = ArgumentCaptor.forClass(AuditRecord.class);
        verify(audit).recordAsync(audited.capture());
        assertThat(audited.getValue().getDetails()).containsEntry("baselines", "SEALED");
    }

    /**
     * A package that sealed that its decision found no baseline is drawn again with none: a baseline learned since is
     * not taken for the one the decision had.
     */
    @Test
    void aPackageThatSealedThatThereWasNoBaselineIsReplayedWithNone() {
        sealed.setBaselineSnapshotJson("{\"baselineEstablished\":false,"
                + "\"decisionBaselines\":{\"personal\":null,\"organization\":null}}");
        when(packages.findByPackageId("pkg-1")).thenReturn(Optional.of(sealed));
        when(service.replay(any(), any(), any(), any(), any(), any())).thenReturn(result("CHALLENGE", null));

        Replayed replayed = replays.replayPackage("admin-1", "pkg-1", new ReplayRequest(BUNDLE, null, null, null))
                .orElseThrow();

        assertThat(replayed.baselines()).isEqualTo(Baselines.SEALED);
        verify(service).replay(eq(sealed), isNull(), isNull(), eq(BUNDLE), any(), eq(List.of()));
        verifyNoInteractions(baselines);
    }

    /**
     * A package sealed before the baselines were has a baseline snapshot without them and is replayed as it always
     * was, with the baselines kept now.
     */
    @Test
    void aPackageSealedBeforeTheBaselinesIsReplayedWithTheOnesKeptNow() {
        sealed.setBaselineSnapshotJson("{\"baselineEstablished\":true,\"isNewUser\":false}");
        when(packages.findByPackageId("pkg-1")).thenReturn(Optional.of(sealed));
        BaselineVector kept = BaselineVector.builder().userId("tenant-a::alice")
                .normalIpRanges(new String[]{"192.0.2.0/24"}).build();
        when(baselines.getUserBaseline("tenant-a::alice")).thenReturn(kept);
        when(service.replay(any(), any(), any(), any(), any(), any())).thenReturn(result("ALLOW", null));

        Replayed replayed = replays.replayPackage("admin-1", "pkg-1", new ReplayRequest(BUNDLE, null, null, null))
                .orElseThrow();

        assertThat(replayed.baselines()).isEqualTo(Baselines.CURRENT);
        ArgumentCaptor<BaselineVector> user = ArgumentCaptor.forClass(BaselineVector.class);
        verify(service).replay(eq(sealed), user.capture(), any(), eq(BUNDLE), any(), eq(List.of()));
        assertThat(user.getValue().getNormalIpRanges()).containsExactly("192.0.2.0/24");
    }

    /** Baselines given with the replay come before the ones the package sealed. */
    @Test
    void baselinesGivenWithTheReplayComeBeforeTheSealedOnes() throws Exception {
        sealed.setBaselineSnapshotJson("{\"decisionBaselines\":{\"personal\":null,\"organization\":null}}");
        when(packages.findByPackageId("pkg-1")).thenReturn(Optional.of(sealed));
        when(service.replay(any(), any(), any(), any(), any(), any())).thenReturn(result("ALLOW", null));
        BaselineVector given = BaselineVector.builder().normalIpRanges(new String[]{"10.9.0.0/16"}).build();

        Replayed replayed = replays.replayPackage("admin-1", "pkg-1", new ReplayRequest(BUNDLE, null,
                JSON.valueToTree(given), null)).orElseThrow();

        assertThat(replayed.baselines()).isEqualTo(Baselines.GIVEN);
        ArgumentCaptor<BaselineVector> user = ArgumentCaptor.forClass(BaselineVector.class);
        verify(service).replay(eq(sealed), user.capture(), isNull(), eq(BUNDLE), any(), eq(List.of()));
        assertThat(user.getValue().getNormalIpRanges()).containsExactly("10.9.0.0/16");
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
                new SealedDecisionReplays(packages, () -> null, baselines, audit, JSON, integrity));
        assertThat(withoutPipeline.replayRequest("req-1", new ReplayRequest(BUNDLE, null, null, null), operator)
                .getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        assertThat(SealedDecisionReplayApiController.class.getAnnotation(PreAuthorize.class).value())
                .isEqualTo("hasAuthority('ROLE_ADMIN')");
        assertThat(SealedDecisionReplayApiController.class.getAnnotation(RequestMapping.class).value())
                .containsExactly("/contexa/admin/api/sealed-decisions");
    }

    /** PR-77: a package changed after its seal is still replayed; the answer and the audit say what it was drawn from. */
    @Test
    void aPackageChangedAfterItsSealIsReplayedAndTheAnswerAndTheAuditSaySo() throws Exception {
        seal();
        sealed.setDecisionJson("{\"action\":\"BLOCK\"}");
        when(packages.findByPackageId("pkg-1")).thenReturn(Optional.of(sealed));
        when(service.replay(any(), any(), any(), any(), any(), any())).thenReturn(result("BLOCK", null));

        Replayed replayed = replays.replayPackage("admin-1", "pkg-1", new ReplayRequest(BUNDLE, null, null, null))
                .orElseThrow();

        assertThat(replayed.integrity()).isEqualTo(SealedEvidencePackageIntegrity.Status.MISMATCH);
        assertThat(replayed.result().action()).as("the replay is not refused").isEqualTo("BLOCK");
        assertThat(JSON.readTree(JSON.writeValueAsString(replayed)).path("integrity").asText()).isEqualTo("MISMATCH");
        ArgumentCaptor<AuditRecord> audited = ArgumentCaptor.forClass(AuditRecord.class);
        verify(audit).recordAsync(audited.capture());
        assertThat(audited.getValue().getDetails()).containsEntry("integrity", "MISMATCH");
    }

    @Test
    void anIntactPackageReadsVerified() {
        seal();
        when(packages.findByPackageId("pkg-1")).thenReturn(Optional.of(sealed));
        when(service.replay(any(), any(), any(), any(), any(), any())).thenReturn(result("ALLOW", null));

        Replayed replayed = replays.replayPackage("admin-1", "pkg-1", new ReplayRequest(BUNDLE, null, null, null))
                .orElseThrow();

        assertThat(replayed.integrity()).isEqualTo(SealedEvidencePackageIntegrity.Status.VERIFIED);
        ArgumentCaptor<AuditRecord> audited = ArgumentCaptor.forClass(AuditRecord.class);
        verify(audit).recordAsync(audited.capture());
        assertThat(audited.getValue().getDetails()).containsEntry("integrity", "VERIFIED");
    }

    @Test
    void aPackageThatCannotBeVerifiedSaysSo() {
        sealed.setPackageHash(null);
        when(packages.findByPackageId("pkg-1")).thenReturn(Optional.of(sealed));
        when(service.replay(any(), any(), any(), any(), any(), any())).thenReturn(result("ALLOW", null));

        Replayed replayed = replays.replayPackage("admin-1", "pkg-1", new ReplayRequest(BUNDLE, null, null, null))
                .orElseThrow();

        assertThat(replayed.integrity()).isEqualTo(SealedEvidencePackageIntegrity.Status.UNVERIFIABLE);
    }

    /**
     * K71: the state of a package is told without the decision pipeline, as a replay tells it, for the version screen
     * that shows its user prompt; nothing is asked or audited.
     */
    @Test
    void theStateOfAPackageIsToldWithoutThePipeline() {
        SealedDecisionReplays withoutPipeline = new SealedDecisionReplays(packages, () -> null, baselines, audit, JSON,
                integrity);
        when(packages.findByPackageId("pkg-1")).thenReturn(Optional.of(sealed));

        assertThat(withoutPipeline.integrity("pkg-1")).contains(SealedEvidencePackageIntegrity.Status.UNVERIFIABLE);
        seal();
        assertThat(withoutPipeline.integrity("pkg-1")).contains(SealedEvidencePackageIntegrity.Status.VERIFIED);
        sealed.setDecisionJson("{\"action\":\"BLOCK\"}");
        assertThat(withoutPipeline.integrity("pkg-1")).contains(SealedEvidencePackageIntegrity.Status.MISMATCH);
        assertThat(withoutPipeline.integrity("pkg-gone")).isEmpty();
        verifyNoInteractions(service, audit);
    }

    /** A replay that gave no answer is audited with the package's state as well. */
    @Test
    void aFailedReplayStillTellsThePackagesState() {
        seal();
        sealed.setCanonicalContextJson("{}");
        when(packages.findByPackageId("pkg-1")).thenReturn(Optional.of(sealed));
        when(service.replay(any(), any(), any(), any(), any(), any())).thenReturn(result(null, "TimeoutException"));

        Replayed replayed = replays.replayPackage("admin-1", "pkg-1", new ReplayRequest(BUNDLE, null, null, null))
                .orElseThrow();

        assertThat(replayed.integrity()).isEqualTo(SealedEvidencePackageIntegrity.Status.MISMATCH);
        ArgumentCaptor<AuditRecord> audited = ArgumentCaptor.forClass(AuditRecord.class);
        verify(audit).recordAsync(audited.capture());
        assertThat(audited.getValue().getOutcome()).isEqualTo("FAILED");
        assertThat(audited.getValue().getDetails()).containsEntry("integrity", "MISMATCH");
    }

    /**
     * Quality plan 3.2, 5 stage 3: a decision that is in no store (a labelled case built in memory in the sealed form)
     * is replayed from the inputs and the baselines given with it: no package is looked up, the baselines kept now are
     * not read, the context format of its inputs goes to the replay, and there is no seal whose state could be told.
     */
    @Test
    void aDecisionThatIsInNoStoreIsReplayedFromItsGivenInputsAndBaselines() {
        when(service.replay(any(), any(), any(), any(), any(), any())).thenReturn(result("CHALLENGE", null));
        SealedEvidencePackage given = sealed();
        given.setPackageId("case-17");
        given.setCorrelationId("case-17");
        BaselineVector person = BaselineVector.builder().userId("template-user")
                .normalIpRanges(new String[]{"10.9.0.0/16"}).build();
        BaselineVector organization = BaselineVector.builder().userId("org:org-a")
                .normalOperatingSystems(new String[]{"LINUX"}).build();

        Replayed replayed = replays.replayGiven("admin-1", given, " 1 ", new ReplayRequest(BUNDLE, List.of("m2"),
                JSON.valueToTree(person), JSON.valueToTree(organization), null));

        assertThat(replayed.result().action()).isEqualTo("CHALLENGE");
        assertThat(replayed.baselines()).isEqualTo(Baselines.GIVEN);
        assertThat(replayed.integrity()).as("it was never sealed").isNull();
        ArgumentCaptor<SealedDecisionReplayService.Request> asked =
                ArgumentCaptor.forClass(SealedDecisionReplayService.Request.class);
        verify(service).replay(asked.capture());
        assertThat(asked.getValue().sealed()).isSameAs(given);
        assertThat(asked.getValue().personalBaseline().getNormalIpRanges()).containsExactly("10.9.0.0/16");
        assertThat(asked.getValue().personalBaseline().getUserId()).as("read under the decision's user")
                .isEqualTo("alice");
        assertThat(asked.getValue().organizationBaseline().getNormalOperatingSystems()).containsExactly("LINUX");
        assertThat(asked.getValue().bundleVersion()).isEqualTo(BUNDLE);
        assertThat(asked.getValue().timeout()).isEqualTo(SealedDecisionReplays.TIMEOUT);
        assertThat(asked.getValue().secondPassModels()).containsExactly("m2");
        assertThat(asked.getValue().configuredSecondPass()).isFalse();
        assertThat(asked.getValue().contextFormatVersion()).isEqualTo("1");
        verifyNoInteractions(packages, baselines);
        ArgumentCaptor<AuditRecord> audited = ArgumentCaptor.forClass(AuditRecord.class);
        verify(audit).recordAsync(audited.capture());
        assertThat(audited.getValue().getEventCategory()).isEqualTo(AuditEventCategory.SEALED_DECISION_REPLAYED);
        assertThat(audited.getValue().getDetails()).containsEntry("packageId", "case-17").containsEntry("given", true)
                .containsEntry("integrity", "NOT_SEALED").containsEntry("baselines", "GIVEN");
    }

    /**
     * A given decision brings every input with it: without a baseline given with it or kept in its baseline snapshot it
     * had none, and the baselines Contexa keeps now are not read in their place, so the same case is the same input
     * whatever the server has learned since. A baseline its snapshot keeps is the one it is drawn with.
     */
    @Test
    void aGivenDecisionIsNeverDrawnWithTheBaselinesKeptNow() {
        when(service.replay(any(), any(), any(), any(), any(), any())).thenReturn(result("ALLOW", null));
        SealedEvidencePackage withoutBaselines = sealed();
        SealedEvidencePackage keeping = sealed();
        ObjectNode snapshot = JSON.createObjectNode().put("baselineEstablished", true);
        snapshot.set(SealedDecisionBaselines.KEY, SealedDecisionBaselines.write(new DecisionBaselines(
                BaselineVector.builder().userId("tenant-a::alice").updateCount(42L).build(), null), JSON));
        keeping.setBaselineSnapshotJson(snapshot.toString());

        Replayed none = replays.replayGiven("admin-1", withoutBaselines, "1", new ReplayRequest(BUNDLE, null, null, null));
        Replayed kept = replays.replayGiven("admin-1", keeping, "1", new ReplayRequest(BUNDLE, null, null, null));

        assertThat(none.baselines()).as("none, as given").isEqualTo(Baselines.GIVEN);
        assertThat(kept.baselines()).isEqualTo(Baselines.SEALED);
        verify(service).replay(eq(withoutBaselines), isNull(), isNull(), eq(BUNDLE), any(), eq(List.of()));
        ArgumentCaptor<BaselineVector> user = ArgumentCaptor.forClass(BaselineVector.class);
        verify(service).replay(eq(keeping), user.capture(), isNull(), eq(BUNDLE), any(), eq(List.of()));
        assertThat(user.getValue().getUpdateCount()).isEqualTo(42L);
        verifyNoInteractions(packages, baselines);
    }

    /** A given decision names the context format of its inputs, and needs the engine's pipeline like any replay. */
    @Test
    void aGivenDecisionNamesTheContextFormatOfItsInputs() {
        ReplayRequest request = new ReplayRequest(BUNDLE, null, null, null);

        assertThatThrownBy(() -> replays.replayGiven("admin-1", sealed(), null, request))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("context format");
        assertThatThrownBy(() -> replays.replayGiven("admin-1", sealed(), "  ", request))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> replays.replayGiven("admin-1", sealed(), "1",
                new ReplayRequest("v0-unknown", null, null, null))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new SealedDecisionReplays(packages, () -> null, baselines, audit, JSON, integrity)
                .replayGiven("admin-1", sealed(), "1", request))
                .isInstanceOf(SealedDecisionReplays.UnavailableException.class);
        verifyNoInteractions(audit);
    }

    /**
     * Quality plan 3.3: the second pass is asked with the second layer's own model, the one the server is set to, when
     * the request says so; it counts as one of the models a replay may ask, and a request body that does not name it
     * asks the named models only, as before.
     */
    @Test
    void theSecondPassIsAskedWithTheServersOwnModelWhenTheRequestSaysSo() throws Exception {
        when(packages.findByPackageId("pkg-1")).thenReturn(Optional.of(sealed));
        when(service.replay(any(), any(), any(), any(), any(), any())).thenReturn(result("ESCALATE", null));

        replays.replayPackage("admin-1", "pkg-1", new ReplayRequest(BUNDLE, List.of("m2"), null, null, true))
                .orElseThrow();

        ArgumentCaptor<SealedDecisionReplayService.Request> asked =
                ArgumentCaptor.forClass(SealedDecisionReplayService.Request.class);
        verify(service).replay(asked.capture());
        assertThat(asked.getValue().configuredSecondPass()).isTrue();
        assertThat(asked.getValue().secondPassModels()).containsExactly("m2");
        assertThat(asked.getValue().contextFormatVersion()).as("a package of the store names no format").isNull();
        ArgumentCaptor<AuditRecord> audited = ArgumentCaptor.forClass(AuditRecord.class);
        verify(audit).recordAsync(audited.capture());
        assertThat(audited.getValue().getDetails()).containsEntry("configuredSecondPass", true)
                .containsEntry("given", false);
        assertThatThrownBy(() -> replays.replayPackage("admin-1", "pkg-1",
                new ReplayRequest(BUNDLE, List.of("a", "b", "c"), null, null, true)))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("second-pass");
        ReplayRequest named = JSON.readValue("{\"bundleVersion\":\"" + BUNDLE + "\",\"secondPassModels\":[\"m2\"]}",
                ReplayRequest.class);
        ReplayRequest own = JSON.readValue("{\"bundleVersion\":\"" + BUNDLE + "\",\"configuredSecondPass\":true}",
                ReplayRequest.class);
        assertThat(named.configuredSecondPass()).isNull();
        assertThat(named.secondPassModels()).containsExactly("m2");
        assertThat(own.configuredSecondPass()).isTrue();
    }

    private void seal() {
        sealed.setPackageHash(integrity.computeHash(sealed));
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
