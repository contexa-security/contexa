package io.contexa.autoconfigure.iam.aiam;

import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexacore.std.pipeline.streaming.StreamingProperties;
import io.contexa.contexaiam.aiam.protocol.context.PolicyContext;
import io.contexa.contexaiam.aiam.protocol.context.StudioQueryContext;
import io.contexa.contexaiam.aiam.web.*;
import io.contexa.contexaiam.properties.SecurityStepUpProperties;
import io.contexa.contexaiam.repository.ConditionTemplateRepository;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.resource.service.ConditionCompatibilityService;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;


@AutoConfiguration
@EnableConfigurationProperties(SecurityStepUpProperties.class)
public class IamAiamWebAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public AiStudioController aiStudioController(
            AICoreOperations<StudioQueryContext> aiNativeProcessor,
            StreamingProperties streamingProperties) {
        return new AiStudioController(aiNativeProcessor, streamingProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public AiApiController aiApiController(
            AICoreOperations<PolicyContext> aiNativeProcessor,
            ConditionTemplateRepository conditionTemplateRepository,
            ManagedResourceRepository managedResourceRepository,
            ConditionCompatibilityService conditionCompatibilityService,
            StreamingProperties streamingProperties) {
        return new AiApiController(aiNativeProcessor, conditionTemplateRepository, managedResourceRepository, conditionCompatibilityService, streamingProperties);
    }
}
