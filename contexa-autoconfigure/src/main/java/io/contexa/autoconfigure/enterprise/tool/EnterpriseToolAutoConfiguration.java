package io.contexa.autoconfigure.enterprise.tool;

import io.contexa.autoconfigure.properties.ContextaProperties;
import io.contexa.contexacoreenterprise.config.EnterpriseBeanConfiguration;
import io.contexa.contexacoreenterprise.config.ToolCallingConfiguration;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Import;

/**
 * Enterprise Tool AutoConfiguration
 *
 * Contexa Enterprise 모듈의 Tool Calling 자동 구성을 제공합니다.
 * Import 방식으로 기존 Configuration 클래스들을 재사용합니다.
 *
 * 포함된 Configuration:
 * - ToolCallingConfiguration - Spring AI Tool Calling 시스템
 * - EnterpriseBeanConfiguration - Enterprise Bean Export
 *
 * 활성화 조건:
 * contexa:
 *   enterprise:
 *     enabled: true
 *
 * @since 0.1.0-ALPHA
 */
@AutoConfiguration
@ConditionalOnProperty(
    prefix = "contexa.enterprise",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = false
)
@EnableConfigurationProperties(ContextaProperties.class)
@ConditionalOnClass(name = "io.contexa.contexacoreenterprise.config.ToolCallingConfiguration")
@Import({
    ToolCallingConfiguration.class,
    EnterpriseBeanConfiguration.class
})
public class EnterpriseToolAutoConfiguration {

    /**
     * Constructor
     *
     * Import된 Configuration 클래스들이 자동으로 등록됩니다.
     * 각 Configuration은 자체적으로 @Conditional 조건을 가질 수 있습니다.
     */
    public EnterpriseToolAutoConfiguration() {
        // Import만 수행, 추가 Bean 등록은 Import된 Configuration에서
    }
}
