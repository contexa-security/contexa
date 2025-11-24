package io.contexa.autoconfigure.core.llm;

import io.contexa.autoconfigure.core.advisor.CoreAdvisorAutoConfiguration;
import io.contexa.autoconfigure.core.infrastructure.CoreInfrastructureAutoConfiguration;
import io.contexa.autoconfigure.core.std.CoreStdComponentsAutoConfiguration;
import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Import;

/**
 * Core LLM AutoConfiguration
 *
 * Contexa 프레임워크의 LLM 관련 자동 구성을 제공합니다.
 *
 * 포함된 Configuration:
 * - PipelineConfiguration (Import) - Pipeline 오케스트레이션
 *
 * 의존성 AutoConfiguration:
 * - CoreLLMTieredAutoConfiguration - 3계층 보안 시스템 (@AutoConfigureAfter)
 * - CoreAdvisorAutoConfiguration - Spring AI Advisor 시스템 (@AutoConfigureAfter)
 *
 * 활성화 조건:
 * contexa:
 *   llm:
 *     enabled: true  (기본값)
 *
 * @since 0.1.0-ALPHA
 */
@AutoConfiguration
@AutoConfigureAfter({
    CoreInfrastructureAutoConfiguration.class,
    CoreStdComponentsAutoConfiguration.class,
    CoreLLMTieredAutoConfiguration.class,
    CoreAdvisorAutoConfiguration.class
})
@ConditionalOnProperty(
    prefix = "contexa.llm",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = true
)
@EnableConfigurationProperties(ContexaProperties.class)
@Import({
    PipelineConfiguration.class
})
public class CoreLLMAutoConfiguration {

    /**
     * Constructor
     *
     * Import된 Configuration 클래스들이 자동으로 등록됩니다.
     * 각 Configuration은 자체적으로 @Conditional 조건을 가질 수 있습니다.
     */
    public CoreLLMAutoConfiguration() {
        // Import만 수행, 추가 Bean 등록은 Import된 Configuration에서
    }
}
