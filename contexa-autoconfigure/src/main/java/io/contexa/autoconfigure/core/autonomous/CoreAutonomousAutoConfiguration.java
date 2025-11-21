package io.contexa.autoconfigure.core.autonomous;

import io.contexa.autoconfigure.properties.ContextaProperties;
import io.contexa.contexacore.autonomous.config.SecurityPlaneConfiguration;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Import;

/**
 * Core Autonomous AutoConfiguration
 *
 * Contexa 프레임워크의 Autonomous Security Plane 자동 구성을 제공합니다.
 * Import 방식과 ComponentScan 방식을 혼합하여 사용합니다.
 *
 * 포함된 Configuration:
 * - SecurityPlaneConfiguration - Security Plane 기본 설정
 *
 * 포함된 컴포넌트:
 * - SecurityPlaneAgent - Autonomous Security Plane 에이전트
 * - 기타 Autonomous 관련 서비스들
 *
 * 활성화 조건:
 * contexa:
 *   autonomous:
 *     enabled: true  (기본값)
 *
 * @since 0.1.0-ALPHA
 */
@AutoConfiguration
@ConditionalOnProperty(
    prefix = "contexa.autonomous",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = true
)
@EnableConfigurationProperties(ContextaProperties.class)
@ConditionalOnClass(name = "io.contexa.contexacore.autonomous.SecurityPlaneAgent")
@Import({
    SecurityPlaneConfiguration.class
})
@ComponentScan(basePackages = "io.contexa.contexacore.autonomous")
public class CoreAutonomousAutoConfiguration {

    /**
     * Constructor
     *
     * Import된 Configuration과 ComponentScan을 통해 Autonomous 관련 컴포넌트가 등록됩니다.
     */
    public CoreAutonomousAutoConfiguration() {
        // Import와 ComponentScan 수행
    }
}
