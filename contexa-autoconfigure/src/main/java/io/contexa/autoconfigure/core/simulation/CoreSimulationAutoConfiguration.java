package io.contexa.autoconfigure.core.simulation;

import io.contexa.autoconfigure.core.infrastructure.CoreInfrastructureAutoConfiguration;
import io.contexa.autoconfigure.properties.ContextaProperties;
import io.contexa.contexacore.infra.SimulationDataInitializer;
import io.contexa.contexacore.repository.ApprovalNotificationRepository;
import io.contexa.contexacore.repository.AttackResultRepository;
import io.contexa.contexacore.repository.SecurityActionRepository;
import io.contexa.contexacore.repository.SecurityIncidentRepository;
import io.contexa.contexacore.repository.SoarApprovalRequestRepository;
import io.contexa.contexacore.repository.ThreatIndicatorRepository;
import io.contexa.contexacore.simulation.config.SimulationConfiguration;
import io.contexa.contexacore.simulation.config.SimulationWebSocketConfig;
import io.contexa.contexacore.simulation.factory.AttackStrategyFactory;
import io.contexa.contexacore.simulation.generator.AttackScenarioGenerator;
import io.contexa.contexacore.simulation.service.DualModeSimulationService;
import io.contexa.contexacore.simulation.service.SimulationStatisticsService;
import io.contexa.contexacore.simulation.tracker.DataBreachTracker;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.kafka.core.KafkaTemplate;

/**
 * Core Simulation AutoConfiguration
 *
 * Contexa 프레임워크의 Simulation 관련 자동 구성을 제공합니다.
 * @Bean 방식으로 Simulation 서비스들을 명시적으로 등록합니다.
 *
 * 포함된 Configuration:
 * - SimulationConfiguration - Simulation 기본 설정
 * - SimulationWebSocketConfig - WebSocket 설정
 *
 * 포함된 컴포넌트 (3개):
 * - SimulationStatisticsService - 시뮬레이션 통계 서비스
 * - DualModeSimulationService - 이중 모드 시뮬레이션 서비스
 * - SimulationDataInitializer - 시뮬레이션 데이터 초기화 (조건부)
 *
 * 활성화 조건:
 * contexa:
 *   simulation:
 *     enabled: false  (기본값: 비활성화)
 *
 * @since 0.1.0-ALPHA
 */
@AutoConfiguration
@AutoConfigureAfter(CoreInfrastructureAutoConfiguration.class)
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
public class CoreSimulationAutoConfiguration {

    public CoreSimulationAutoConfiguration() {
        // @Bean 방식으로 Simulation 서비스 등록
    }

    /**
     * 1. SimulationStatisticsService - 시뮬레이션 통계 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnClass(name = "io.contexa.contexacore.simulation.service.SimulationStatisticsService")
    public SimulationStatisticsService simulationStatisticsService(
            RedisTemplate<String, Object> redisTemplate,
            StringRedisTemplate stringRedisTemplate) {
        return new SimulationStatisticsService(redisTemplate, stringRedisTemplate);
    }

    /**
     * 2. DualModeSimulationService - 이중 모드 시뮬레이션 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnClass(name = "io.contexa.contexacore.simulation.service.DualModeSimulationService")
    public DualModeSimulationService dualModeSimulationService(
            AttackStrategyFactory strategyFactory,
            AttackScenarioGenerator scenarioGenerator,
            AttackResultRepository attackResultRepository,
            DataBreachTracker dataBreachTracker) {
        return new DualModeSimulationService(
            strategyFactory, scenarioGenerator, attackResultRepository, dataBreachTracker
        );
    }

    /**
     * 3. SimulationDataInitializer - 시뮬레이션 데이터 초기화 (조건부)
     */
    @Bean
    @ConditionalOnProperty(prefix = "contexa.simulation.data", name = "enabled", havingValue = "true")
    @ConditionalOnMissingBean
    @ConditionalOnClass(name = "io.contexa.contexacore.infra.SimulationDataInitializer")
    public SimulationDataInitializer simulationDataInitializer(
            SecurityIncidentRepository securityIncidentRepository,
            ThreatIndicatorRepository threatIndicatorRepository,
            SecurityActionRepository securityActionRepository,
            SoarApprovalRequestRepository soarApprovalRequestRepository,
            ApprovalNotificationRepository approvalNotificationRepository,
            @Autowired(required = false) KafkaTemplate<String, Object> kafkaTemplate) {
        return new SimulationDataInitializer(
            securityIncidentRepository, threatIndicatorRepository, securityActionRepository,
            soarApprovalRequestRepository, approvalNotificationRepository, kafkaTemplate
        );
    }
}
