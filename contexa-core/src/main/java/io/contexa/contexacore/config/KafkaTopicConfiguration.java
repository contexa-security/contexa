package io.contexa.contexacore.config;

import org.apache.kafka.common.config.TopicConfig;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.TopicBuilder;
import org.springframework.kafka.core.KafkaAdmin;

/**
 * Kafka 토픽 사전 생성 설정
 *
 * 토픽을 사전에 생성하여 메시지 손실을 방지합니다.
 * Kafka의 auto.create.topics.enable=true 설정에서도
 * 첫 번째 메시지가 손실될 수 있으므로 명시적으로 토픽을 생성합니다.
 *
 * 각 토픽은 다음을 설정합니다:
 * - 파티션 수: 동시 처리량 제어
 * - 복제 계수: 장애 복구 (개발: 1, 프로덕션: 3 권장)
 * - 보존 기간: 데이터 저장 기간
 */
@Configuration
public class KafkaTopicConfiguration {

    /**
     * Kafka Admin - Spring Boot가 자동으로 토픽을 생성하도록 함
     */
    @Bean
    public KafkaAdmin.NewTopics allSecurityTopics() {
        return new KafkaAdmin.NewTopics(
            // Tiered 인증 이벤트 토픽 (Critical, Contextual, General)
            authEventsCriticalTopic().build(),
            authEventsContextualTopic().build(),
            authEventsGeneralTopic().build(),

            // 도메인별 이벤트 토픽
            securityAuthorizationEventsTopic().build(),
            securityIncidentEventsTopic().build(),
            securityAuditEventsTopic().build(),

            // 일반 보안 이벤트 토픽
            securityEventsTopic().build(),
            threatIndicatorsTopic().build(),
            networkEventsTopic().build(),

            // Dead Letter Queue
            deadLetterQueueTopic().build()
        );
    }

    /**
     * Critical 인증 이벤트 토픽
     * - 무차별 대입 공격, Credential Stuffing 등 긴급 이벤트
     * - 높은 처리 우선순위
     */
    private TopicBuilder authEventsCriticalTopic() {
        return TopicBuilder.name("auth-events-critical")
            .partitions(3)  // 병렬 처리를 위한 파티션
            .replicas(1)    // 개발: 1, 프로덕션: 3 권장
            .config(TopicConfig.RETENTION_MS_CONFIG, "604800000")  // 7일 보존
            .config(TopicConfig.MIN_IN_SYNC_REPLICAS_CONFIG, "1")  // 최소 동기화 복제본
            .compact();  // 로그 압축 활성화
    }

    /**
     * Contextual 인증 이벤트 토픽
     * - 중간 위험도 이벤트
     * - 컨텍스트 분석이 필요한 이벤트
     */
    private TopicBuilder authEventsContextualTopic() {
        return TopicBuilder.name("auth-events-contextual")
            .partitions(3)
            .replicas(1)
            .config(TopicConfig.RETENTION_MS_CONFIG, "604800000");  // 7일
    }

    /**
     * General 인증 이벤트 토픽
     * - 일반 인증 이벤트
     * - 낮은 위험도
     */
    private TopicBuilder authEventsGeneralTopic() {
        return TopicBuilder.name("auth-events-general")
            .partitions(3)
            .replicas(1)
            .config(TopicConfig.RETENTION_MS_CONFIG, "259200000");  // 3일
    }

    /**
     * 인가 결정 이벤트 토픽
     * - 접근 제어 결정 이벤트
     */
    private TopicBuilder securityAuthorizationEventsTopic() {
        return TopicBuilder.name("security-authorization-events")
            .partitions(3)
            .replicas(1)
            .config(TopicConfig.RETENTION_MS_CONFIG, "604800000");  // 7일
    }

    /**
     * 보안 인시던트 이벤트 토픽
     * - 보안 사고 및 위반 이벤트
     * - 장기 보존
     */
    private TopicBuilder securityIncidentEventsTopic() {
        return TopicBuilder.name("security-incident-events")
            .partitions(3)
            .replicas(1)
            .config(TopicConfig.RETENTION_MS_CONFIG, "2592000000");  // 30일 보존
    }

    /**
     * 감사 로그 이벤트 토픽
     * - 컴플라이언스를 위한 감사 로그
     * - 장기 보존
     */
    private TopicBuilder securityAuditEventsTopic() {
        return TopicBuilder.name("security-audit-events")
            .partitions(3)
            .replicas(1)
            .config(TopicConfig.RETENTION_MS_CONFIG, "7776000000");  // 90일 보존 (컴플라이언스)
    }

    /**
     * 일반 보안 이벤트 토픽
     * - 범용 보안 이벤트
     */
    private TopicBuilder securityEventsTopic() {
        return TopicBuilder.name("security-events")
            .partitions(5)  // 높은 처리량
            .replicas(1)
            .config(TopicConfig.RETENTION_MS_CONFIG, "604800000");  // 7일
    }

    /**
     * 위협 지표 토픽
     * - 외부 위협 인텔리전스
     */
    private TopicBuilder threatIndicatorsTopic() {
        return TopicBuilder.name("threat-indicators")
            .partitions(3)
            .replicas(1)
            .config(TopicConfig.RETENTION_MS_CONFIG, "1209600000");  // 14일
    }

    /**
     * 네트워크 이벤트 토픽
     * - 방화벽, IDS/IPS 이벤트
     */
    private TopicBuilder networkEventsTopic() {
        return TopicBuilder.name("network-events")
            .partitions(5)  // 높은 처리량
            .replicas(1)
            .config(TopicConfig.RETENTION_MS_CONFIG, "259200000");  // 3일
    }

    /**
     * Dead Letter Queue 토픽
     * - 처리 실패한 메시지 저장
     * - 디버깅 및 재처리를 위해 장기 보존
     */
    private TopicBuilder deadLetterQueueTopic() {
        return TopicBuilder.name("security-events-dlq")
            .partitions(1)  // DLQ는 순서 보장을 위해 파티션 1개
            .replicas(1)
            .config(TopicConfig.RETENTION_MS_CONFIG, "2592000000");  // 30일 보존
    }
}
