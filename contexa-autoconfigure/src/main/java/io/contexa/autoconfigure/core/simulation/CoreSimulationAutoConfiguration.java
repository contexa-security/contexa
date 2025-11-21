package io.contexa.autoconfigure.core.simulation;

import io.contexa.autoconfigure.properties.ContextaProperties;
import io.contexa.contexacore.simulation.config.SimulationConfiguration;
import io.contexa.contexacore.simulation.config.SimulationWebSocketConfig;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Import;

/**
 * Core Simulation AutoConfiguration
 *
 * Contexa 프레임워크의 Simulation 관련 자동 구성을 제공합니다.
 * Import 방식과 ComponentScan 방식을 혼합하여 사용합니다.
 *
 * 포함된 Configuration:
 * - SimulationConfiguration - Simulation 기본 설정
 * - SimulationWebSocketConfig - WebSocket 설정
 *
 * 포함된 컴포넌트:
 * - Simulation 관련 서비스들
 *
 * 활성화 조건:
 * contexa:
 *   simulation:
 *     enabled: false  (기본값: 비활성화)
 *
 * @since 0.1.0-ALPHA
 */
@AutoConfiguration
@ConditionalOnProperty(
    prefix = "contexa.simulation",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = false
)
@EnableConfigurationProperties(ContextaProperties.class)
@ConditionalOnClass(name = "io.contexa.contexacore.simulation.config.SimulationConfiguration")
@Import({
    SimulationConfiguration.class,
    SimulationWebSocketConfig.class
})
@ComponentScan(basePackages = "io.contexa.contexacore.simulation")
public class CoreSimulationAutoConfiguration {

    /**
     * Constructor
     *
     * Import된 Configuration과 ComponentScan을 통해 Simulation 관련 컴포넌트가 등록됩니다.
     */
    public CoreSimulationAutoConfiguration() {
        // Import와 ComponentScan 수행
    }
}
