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
package io.contexa.contexacore.std.components.prompt.governance;

import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceChangeRecord;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceRegistryRecord;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceReleaseWorkflowRecord;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceRollbackRecord;
import io.contexa.contexacore.repository.prompt.PromptGovernanceBudgetProfileRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceChangeRecordRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceEvaluationRecordRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceModelCompatibilityRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceRegistryRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceReleaseApprovalRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceReleaseWorkflowRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceRollbackRecordRepository;
import io.contexa.contexacore.std.components.prompt.PromptReleaseStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * N-GOV-1: an applied release transition writes the rollback ledger only when the bundle declares a rollback target and
 * the transition has a rollback state; a retirement, or a shadow release without a target, leaves the ledger as it is
 * instead of writing a row its NOT NULL columns refuse.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class PromptGovernanceReleaseGateRollbackLedgerTest {

    private static final String SCOPE = PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE;
    private static final String KEY = "cortex.security-decision";
    private static final String VERSION = "2026.10.16-v19.19";

    @Mock
    private PromptGovernanceLifecycleLedgerService lifecycleLedgerService;
    @Mock
    private PromptGovernanceRegistryRepository registryRepository;
    @Mock
    private PromptGovernanceChangeRecordRepository changeRepository;
    @Mock
    private PromptGovernanceEvaluationRecordRepository evaluationRepository;
    @Mock
    private PromptGovernanceReleaseApprovalRepository releaseApprovalRepository;
    @Mock
    private PromptGovernanceRollbackRecordRepository rollbackRepository;
    @Mock
    private PromptGovernanceReleaseWorkflowRepository workflowRepository;
    @Mock
    private PromptGovernanceModelCompatibilityRepository modelCompatibilityRepository;
    @Mock
    private PromptGovernanceBudgetProfileRepository budgetProfileRepository;

    private PromptGovernanceReleaseGateService service;

    @BeforeEach
    void setUp() {
        service = new PromptGovernanceReleaseGateService(lifecycleLedgerService, registryRepository, changeRepository,
                evaluationRepository, releaseApprovalRepository, rollbackRepository, workflowRepository,
                modelCompatibilityRepository, budgetProfileRepository);
        when(workflowRepository.save(any(PromptGovernanceReleaseWorkflowRecord.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        when(changeRepository.findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(SCOPE, KEY,
                VERSION)).thenReturn(Optional.of(PromptGovernanceChangeRecord.builder().promptKey(KEY)
                .promptVersion(VERSION).build()));
    }

    @Test
    void aRetirementIsAppliedAndWritesNoRollbackRow() {
        registry("PRODUCTION", null);

        PromptGovernanceReleaseGateService.ReleaseTransitionReceipt receipt = transition(PromptReleaseStatus.RETIRED);

        assertThat(receipt.applied()).isTrue();
        verify(rollbackRepository, never()).save(any(PromptGovernanceRollbackRecord.class));
    }

    @Test
    void aShadowReleaseWithoutARollbackTargetIsAppliedAndWritesNoRollbackRow() {
        registry("DRAFT", null);

        PromptGovernanceReleaseGateService.ReleaseTransitionReceipt receipt = transition(PromptReleaseStatus.EVAL_ONLY);

        assertThat(receipt.applied()).isTrue();
        verify(rollbackRepository, never()).save(any(PromptGovernanceRollbackRecord.class));
    }

    @Test
    void aShadowReleaseWithARollbackTargetKeepsItsPlannedRollback() {
        registry("DRAFT", "2026.10.16-v20.23");

        PromptGovernanceReleaseGateService.ReleaseTransitionReceipt receipt = transition(PromptReleaseStatus.EVAL_ONLY);

        assertThat(receipt.applied()).isTrue();
        ArgumentCaptor<PromptGovernanceRollbackRecord> saved = ArgumentCaptor.forClass(PromptGovernanceRollbackRecord.class);
        verify(rollbackRepository).save(saved.capture());
        assertThat(saved.getValue().getRollbackTargetPromptVersion()).isEqualTo("2026.10.16-v20.23");
        assertThat(saved.getValue().getRollbackReadinessState()).isEqualTo("PLANNED");
    }

    private PromptGovernanceReleaseGateService.ReleaseTransitionReceipt transition(PromptReleaseStatus target) {
        return service.transitionPromptRelease(SCOPE, KEY, VERSION, target, "platform-admin", "N-GOV-1 test",
                "OSS_OPERATOR_API");
    }

    private void registry(String releaseStatus, String rollbackVersion) {
        when(registryRepository.findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(SCOPE, KEY,
                VERSION)).thenReturn(Optional.of(PromptGovernanceRegistryRecord.builder().registryScope(SCOPE)
                .promptKey(KEY).templateKey("SecurityDecisionStandard").promptVersion(VERSION)
                .contractVersion("CORTEX_PROMPT_CONTRACT_V3")
                .promptArtifactHashSha256("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                .releaseStatus(releaseStatus).owner("contexa-cortex-core").releaseApprovalReference("P5-GOLD-2026-10-16")
                .rollbackPromptVersion(rollbackVersion).changeSummary("summary")
                .templateClassName("SecurityDecisionStandardPromptTemplate").registrationSource("test").build()));
    }
}
