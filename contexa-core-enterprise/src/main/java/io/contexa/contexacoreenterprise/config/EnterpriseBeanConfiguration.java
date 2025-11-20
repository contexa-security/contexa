package io.contexa.contexacoreenterprise.config;

import io.contexa.contexacore.autonomous.ThreatEvaluator;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacore.domain.SoarRequest;
import io.contexa.contexacore.soar.SoarLab;
import io.contexa.contexacoreenterprise.autonomous.evolution.IntegratedThreatEvaluator;
import io.contexa.contexacore.hcad.service.HCADSimilarityCalculator;
import io.contexa.contexacore.plane.ZeroTrustHotPathOrchestrator;
import io.contexa.contexacoreenterprise.plane.ZeroTrustHotPathOrchestratorImpl;
import io.contexa.contexacoreenterprise.soar.lab.SoarLabImpl;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.scheduling.annotation.EnableAsync;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * EnterpriseBeanConfiguration - Enterprise 기능 Bean 등록 설정
 *
 * <p>
 * contexa-core-enterprise 모듈에서 사용 가능한 Enterprise 기능들을
 * Core 인터페이스로 export하여 Spring Boot AutoConfiguration을 통해
 * Core 모듈에 자동으로 주입되도록 합니다.
 * </p>
 *
 * @since 0.1.0-ALPHA
 */
@Slf4j
@Configuration
@EnableAsync(proxyTargetClass = true)
@EnableAspectJAutoProxy(proxyTargetClass = true, exposeProxy = true)
public class EnterpriseBeanConfiguration {

    @Value("${hcad.similarity.hot-path-threshold:0.7}")
    private double hotPathThreshold;

    @Bean
    public SoarLab soarLab(@Autowired(required = false) SoarLabImpl impl) {
        if (impl != null) {
            log.info("SoarLab export 완료");
            return request -> impl.processAsync(request);
        }
        return null;
    }

    @Bean
    public ThreatEvaluator threatEvaluator(@Autowired(required = false) IntegratedThreatEvaluator evaluator) {
        if (evaluator != null) {
            log.info("ThreatEvaluator export 완료");
            return evaluator::evaluateIntegrated;
        }
        return null;
    }

    @Bean
    public ZeroTrustHotPathOrchestrator zeroTrustHotPathOrchestrator(@Autowired(required = false) ZeroTrustHotPathOrchestratorImpl impl) {
        if (impl != null) {
            log.info("ZeroTrustHotPathOrchestrator export 완료");
            return (event, originalResult) -> {
                var decision = impl.evaluateHotPathEvent(event, originalResult);

                // Cold Path 라우팅 결정 시 유사도 조정 (HOT Path 우회)
                if (decision.getDecision() == ZeroTrustHotPathOrchestratorImpl.Decision.ROUTE_TO_COLD_PATH) {
                    // 유사도를 HOT Path 임계값 아래로 강제 조정
                    double adjustedSimilarity = hotPathThreshold - 0.01;

                    log.warn("[ZeroTrust-HCAD] HOT Path 우회: reason={}, originalSim={}, adjustedSim={}",
                            decision.getReason(),
                            String.format("%.3f", originalResult.getFinalSimilarity()),
                            String.format("%.3f", adjustedSimilarity));

                    return HCADSimilarityCalculator.TrustedSimilarityResult.builder()
                            .finalSimilarity(adjustedSimilarity)
                            .trustScore(originalResult.getTrustScore() * 0.5)  // 신뢰도 절반 감소
                            .crossValidationPassed(false)  // Cross-Validation 실패 마킹
                            .threatEvidence("ZeroTrust-RouteToColdPath: " + decision.getReason())
                            .threatType("ZERO_TRUST_VIOLATION")
                            .layer1ThreatSearchScore(originalResult.getLayer1ThreatSearchScore())
                            .layer2BaselineSimilarity(originalResult.getLayer2BaselineSimilarity())
                            .layer3AnomalyScore(originalResult.getLayer3AnomalyScore())
                            .layer4CorrelationScore(originalResult.getLayer4CorrelationScore())
                            .build();
                }

                // Graceful Degradation 상태 로깅
                if (decision.getDecision() == ZeroTrustHotPathOrchestratorImpl.Decision.ALLOW_HOT_PATH_DEGRADED) {
                    log.info("[ZeroTrust-HCAD] HOT Path 허용 (Degraded): reason={}", decision.getReason());
                }

                // HOT Path 허용 시 원본 결과 반환
                return originalResult;
            };
        }
        return null;
    }
}
