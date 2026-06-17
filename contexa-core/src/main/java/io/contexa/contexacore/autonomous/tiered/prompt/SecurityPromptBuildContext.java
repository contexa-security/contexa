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
package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.SecurityEvent;
import io.contexa.contexacore.autonomous.learning.evidence.LearningContextEvidence;
import io.contexa.contexacore.autonomous.context.prompt.PromptRuntimeGovernanceRule;
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import io.contexa.contexacore.std.llm.client.StructuredOutputMode;
import lombok.Getter;
import org.springframework.ai.document.Document;

import java.util.List;

@Getter
public class SecurityPromptBuildContext {

    private final SecurityEvent event;
    private final SecurityDecisionStandardPromptTemplate.SessionContext sessionContext;
    private final SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis;
    private final List<Document> relatedDocuments;
    private final CanonicalSecurityContext canonicalSecurityContext;
    private final String userId;
    private final BaselineStatus baselineStatus;
    private final SecurityDecisionStandardPromptTemplate.DetectedPatterns detectedPatterns;
    private final LearningContextEvidence learningContextEvidence;
    private final PromptBudgetProfile promptBudgetProfile;
    private final StructuredOutputMode structuredOutputMode;
    private final List<PromptRuntimeGovernanceRule> runtimeGovernanceRules;

    public SecurityPromptBuildContext(SecurityEvent event,
                                      SecurityDecisionStandardPromptTemplate.SessionContext sessionContext,
                                      SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis,
                                      List<Document> relatedDocuments,
                                      CanonicalSecurityContext canonicalSecurityContext,
                                      String userId,
                                       BaselineStatus baselineStatus,
                                       SecurityDecisionStandardPromptTemplate.DetectedPatterns detectedPatterns,
                                       LearningContextEvidence learningContextEvidence,
                                       PromptBudgetProfile promptBudgetProfile,
                                       StructuredOutputMode structuredOutputMode) {
        this(event,
                sessionContext,
                behaviorAnalysis,
                relatedDocuments,
                canonicalSecurityContext,
                userId,
                baselineStatus,
                detectedPatterns,
                learningContextEvidence,
                promptBudgetProfile,
                structuredOutputMode,
                List.of());
    }

    public SecurityPromptBuildContext(SecurityEvent event,
                                      SecurityDecisionStandardPromptTemplate.SessionContext sessionContext,
                                      SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis,
                                      List<Document> relatedDocuments,
                                      CanonicalSecurityContext canonicalSecurityContext,
                                      String userId,
                                      BaselineStatus baselineStatus,
                                      SecurityDecisionStandardPromptTemplate.DetectedPatterns detectedPatterns,
                                      LearningContextEvidence learningContextEvidence,
                                      PromptBudgetProfile promptBudgetProfile,
                                      StructuredOutputMode structuredOutputMode,
                                      List<PromptRuntimeGovernanceRule> runtimeGovernanceRules) {
        this.event = event;
        this.sessionContext = sessionContext;
        this.behaviorAnalysis = behaviorAnalysis;
        this.relatedDocuments = relatedDocuments != null ? List.copyOf(relatedDocuments) : List.of();
        this.canonicalSecurityContext = canonicalSecurityContext;
        this.userId = userId;
        this.baselineStatus = baselineStatus;
        this.detectedPatterns = detectedPatterns;
        this.learningContextEvidence = learningContextEvidence;
        this.promptBudgetProfile = promptBudgetProfile;
        this.structuredOutputMode = structuredOutputMode;
        this.runtimeGovernanceRules = runtimeGovernanceRules != null ? List.copyOf(runtimeGovernanceRules) : List.of();
    }

    public SecurityPromptBuildContext withRuntimeGovernanceRules(List<PromptRuntimeGovernanceRule> rules) {
        return new SecurityPromptBuildContext(
                event,
                sessionContext,
                behaviorAnalysis,
                relatedDocuments,
                canonicalSecurityContext,
                userId,
                baselineStatus,
                detectedPatterns,
                learningContextEvidence,
                promptBudgetProfile,
                structuredOutputMode,
                rules);
    }
}
