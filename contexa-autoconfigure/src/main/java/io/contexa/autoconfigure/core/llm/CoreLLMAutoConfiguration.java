package io.contexa.autoconfigure.core.llm;

import io.contexa.autoconfigure.properties.ContextaProperties;
import io.contexa.contexacore.std.advisor.config.AdvisorConfiguration;
import io.contexa.contexacore.std.llm.config.TieredSecurityLLMConfiguration;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Import;

/**
 * Core LLM AutoConfiguration
 *
 * Contexa 프레임워크의 LLM 관련 자동 구성을 제공합니다.
 * Import 방식으로 기존 Configuration 클래스들을 재사용합니다.
 *
 * 포함된 Configuration:
 * - TieredSecurityLLMConfiguration - 3계층 보안 시스템
 * - AdvisorConfiguration - Spring AI Advisor 시스템
 *
 * 활성화 조건:
 * contexa:
 *   llm:
 *     enabled: true  (기본값)
 *
 * @since 0.1.0-ALPHA
 */
@AutoConfiguration
@ConditionalOnProperty(
    prefix = "contexa.llm",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = true
)
@EnableConfigurationProperties(ContextaProperties.class)
@ConditionalOnClass(name = "io.contexa.contexacore.std.llm.config.TieredSecurityLLMConfiguration")
@Import({
    TieredSecurityLLMConfiguration.class,
    AdvisorConfiguration.class
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
