package io.contexa.autoconfigure.core.llm;

import io.contexa.autoconfigure.core.advisor.CoreAdvisorAutoConfiguration;
import io.contexa.autoconfigure.core.infra.CoreInfrastructureAutoConfiguration;
import io.contexa.autoconfigure.core.std.CoreStdComponentsAutoConfiguration;
import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacore.properties.SecurityMappingProperties;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Import;

@AutoConfiguration
@AutoConfigureAfter({
        CoreInfrastructureAutoConfiguration.class,
        CoreStdComponentsAutoConfiguration.class,
        CoreLLMTieredAutoConfiguration.class,
        CoreAdvisorAutoConfiguration.class
})
@ConditionalOnProperty(prefix = "contexa.llm", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties({
        ContexaProperties.class,
        SecurityMappingProperties.class
})
@Import({
        PipelineConfiguration.class
})
public class CoreLLMAutoConfiguration {

    public CoreLLMAutoConfiguration() {

    }
}
