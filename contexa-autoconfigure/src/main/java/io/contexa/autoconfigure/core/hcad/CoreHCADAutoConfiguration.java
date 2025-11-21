package io.contexa.autoconfigure.core.hcad;

import io.contexa.autoconfigure.properties.ContextaProperties;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;

/**
 * Core HCAD AutoConfiguration
 *
 * Contexa 프레임워크의 HCAD 관련 자동 구성을 제공합니다.
 * ComponentScan 방식으로 HCAD 패키지의 모든 컴포넌트를 등록합니다.
 *
 * 포함된 컴포넌트:
 * - HCADAnalysisService - HCAD 분석 서비스
 * - HCADAuthenticationService - HCAD 인증 서비스
 * - HCADFilter - HCAD 필터 (조건부)
 * - 기타 HCAD 관련 서비스들
 *
 * 활성화 조건:
 * contexa:
 *   hcad:
 *     enabled: true  (기본값)
 *
 * @since 0.1.0-ALPHA
 */
@AutoConfiguration
@ConditionalOnProperty(
    prefix = "contexa.hcad",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = true
)
@EnableConfigurationProperties(ContextaProperties.class)
@ConditionalOnClass(name = "io.contexa.contexacore.hcad.service.HCADAnalysisService")
@ComponentScan(basePackages = "io.contexa.contexacore.hcad")
public class CoreHCADAutoConfiguration {

    /**
     * Constructor
     *
     * ComponentScan을 통해 HCAD 패키지의 모든 컴포넌트가 자동으로 등록됩니다.
     */
    public CoreHCADAutoConfiguration() {
        // ComponentScan 수행, HCAD 패키지의 모든 @Service, @Component 등록
    }
}
