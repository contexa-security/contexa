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
package io.contexa.autoconfigure.capability;

import io.contexa.contexacommon.autoconfigure.capability.CapabilityCheckResult;
import io.contexa.contexacommon.autoconfigure.capability.CapabilityContributor;
import io.contexa.contexacommon.autoconfigure.capability.CapabilityRequirement;
import io.contexa.contexacommon.autoconfigure.capability.CapabilityStatus;
import io.contexa.contexacommon.autoconfigure.capability.ContexaCapability;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.util.ClassUtils;

import java.util.ArrayList;
import java.util.List;

public class CoreCapabilityContributor implements CapabilityContributor {

    static final String PROCESSING_STRATEGY_TYPE =
            "io.contexa.contexacore.autonomous.handler.strategy.ProcessingStrategy";
    static final String DECISION_OBSERVATION_STORE_BEAN = "contexaJdbcTemplate";
    private static final List<String> COLD_PATH_STRATEGY_CHAIN = List.of(
            "io.contexa.contexacore.autonomous.processor.ColdPathEventProcessor",
            "io.contexa.contexacore.autonomous.tiered.strategy.Layer1ContextualStrategy",
            "io.contexa.contexacore.autonomous.tiered.strategy.Layer2ExpertStrategy");

    private final ListableBeanFactory beanFactory;
    private final CapabilityRequirementResolver requirementResolver;

    public CoreCapabilityContributor(
            ListableBeanFactory beanFactory,
            CapabilityRequirementResolver requirementResolver) {
        this.beanFactory = beanFactory;
        this.requirementResolver = requirementResolver;
    }

    @Override
    public String contributorName() {
        return "contexa-core";
    }

    @Override
    public List<ContexaCapability> capabilities() {
        return List.of(
                ContexaCapability.LLM_RUNTIME,
                ContexaCapability.EMBEDDING_RUNTIME,
                ContexaCapability.RAG_VECTOR,
                ContexaCapability.SECURITY_LEARNING,
                ContexaCapability.AUTONOMOUS_DECISION,
                ContexaCapability.BRIDGE);
    }

    @Override
    public List<CapabilityCheckResult> check() {
        return List.of(
                check(ContexaCapability.LLM_RUNTIME, List.of(
                        "org.springframework.ai.chat.model.ChatModel",
                        "org.springframework.ai.chat.client.ChatClient",
                        "io.contexa.contexacore.std.llm.client.UnifiedLLMOrchestrator")),
                check(ContexaCapability.EMBEDDING_RUNTIME, List.of(
                        "org.springframework.ai.embedding.EmbeddingModel")),
                check(ContexaCapability.RAG_VECTOR, List.of(
                        "org.springframework.ai.vectorstore.VectorStore",
                        "io.contexa.contexacore.autonomous.tiered.cache.VectorStoreCacheLayer",
                        "io.contexa.contexacore.std.rag.service.UnifiedVectorService")),
                check(ContexaCapability.SECURITY_LEARNING, List.of(
                        "io.contexa.contexacore.autonomous.service.SecurityLearningService",
                        "io.contexa.contexacore.autonomous.tiered.service.SecurityDecisionPostProcessor")),
                // The decision plane only produces decisions when a processing strategy exists, and
                // only enforces them after they are written to the decision observation store.
                check(ContexaCapability.AUTONOMOUS_DECISION, List.of(
                        "io.contexa.contexacore.autonomous.SecurityPlaneAgent",
                        "io.contexa.contexacore.autonomous.service.SynchronousProtectableDecisionService",
                        PROCESSING_STRATEGY_TYPE),
                        List.of(DECISION_OBSERVATION_STORE_BEAN)),
                check(ContexaCapability.BRIDGE, List.of(
                        "io.contexa.contexacommon.security.bridge.web.BridgeResolutionFilter")));
    }

    private CapabilityCheckResult check(ContexaCapability capability, List<String> requiredBeanTypes) {
        return check(capability, requiredBeanTypes, List.of());
    }

    private CapabilityCheckResult check(
            ContexaCapability capability,
            List<String> requiredBeanTypes,
            List<String> requiredBeanNames) {
        CapabilityRequirement requirement = requirementResolver.requirement(capability);
        if (!requirement.enabled()) {
            return new CapabilityCheckResult(
                    capability,
                    CapabilityStatus.INACTIVE_EXPECTED,
                    false,
                    requirement.reason(),
                    List.of(),
                    List.of(),
                    List.of());
        }

        List<String> presentBeans = new ArrayList<>();
        List<String> missingBeans = new ArrayList<>();
        for (String beanType : requiredBeanTypes) {
            if (hasBean(beanType)) {
                presentBeans.add(beanType);
            } else {
                missingBeans.add(beanType);
            }
        }
        for (String beanName : requiredBeanNames) {
            if (beanFactory.containsBean(beanName)) {
                presentBeans.add(beanName);
            } else {
                missingBeans.add(beanName);
            }
        }
        if (missingBeans.contains(PROCESSING_STRATEGY_TYPE)) {
            for (String beanType : COLD_PATH_STRATEGY_CHAIN) {
                if (!hasBean(beanType)) {
                    missingBeans.add(beanType);
                }
            }
        }

        CapabilityStatus status;
        if (missingBeans.isEmpty()) {
            status = CapabilityStatus.ACTIVE;
        } else if (requirement.required()) {
            status = CapabilityStatus.INACTIVE_UNEXPECTED;
        } else {
            status = CapabilityStatus.DEGRADED;
        }

        return new CapabilityCheckResult(
                capability,
                status,
                requirement.required(),
                requirement.reason(),
                presentBeans,
                missingBeans,
                recommendations(capability, missingBeans));
    }

    private List<String> recommendations(ContexaCapability capability, List<String> missingBeans) {
        if (missingBeans.isEmpty()) {
            return List.of();
        }
        List<String> recommendations = requirementResolver.operatorRecommendations(capability, missingBeans);
        if (!recommendations.isEmpty()) {
            return recommendations;
        }
        return List.of("Inspect auto-configuration conditions and missing bean chain for " + capability.propertyKey() + ".");
    }

    private boolean hasBean(String className) {
        if (!ClassUtils.isPresent(className, getClass().getClassLoader())) {
            return false;
        }
        try {
            Class<?> beanType = ClassUtils.forName(className, getClass().getClassLoader());
            return BeanFactoryUtils.beanNamesForTypeIncludingAncestors(beanFactory, beanType, true, false).length > 0;
        } catch (ClassNotFoundException ex) {
            return false;
        }
    }
}
