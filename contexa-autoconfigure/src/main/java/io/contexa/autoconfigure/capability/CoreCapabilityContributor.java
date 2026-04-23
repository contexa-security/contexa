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
                check(ContexaCapability.AUTONOMOUS_DECISION, List.of(
                        "io.contexa.contexacore.autonomous.SecurityPlaneAgent",
                        "io.contexa.contexacore.autonomous.service.SynchronousProtectableDecisionService")),
                check(ContexaCapability.BRIDGE, List.of(
                        "io.contexa.contexacommon.security.bridge.web.BridgeResolutionFilter")));
    }

    private CapabilityCheckResult check(ContexaCapability capability, List<String> requiredBeanTypes) {
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
        return switch (capability) {
            case RAG_VECTOR -> List.of(
                    "Verify Spring AI PgVector starter is on the runtime classpath.",
                    "Verify EmbeddingModel, JdbcTemplate/DataSource, and PgVectorStoreAutoConfiguration are active.",
                    "Verify CoreRAGAutoConfiguration runs after PgVectorStoreAutoConfiguration.");
            case SECURITY_LEARNING -> List.of(
                    "Verify UnifiedVectorService is active when vector-backed post-authentication learning is required.",
                    "Verify CoreAutonomousAutoConfiguration runs after CoreRAGAutoConfiguration.");
            case LLM_RUNTIME -> List.of(
                    "Configure at least one Spring AI ChatModel provider and CONTEXA LLM selection.");
            case EMBEDDING_RUNTIME -> List.of(
                    "Configure a Spring AI EmbeddingModel provider before PgVectorStoreAutoConfiguration.");
            default -> List.of("Inspect auto-configuration conditions and missing bean chain for " + capability.propertyKey() + ".");
        };
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
