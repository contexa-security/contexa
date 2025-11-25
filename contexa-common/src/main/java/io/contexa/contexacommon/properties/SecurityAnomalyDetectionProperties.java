package io.contexa.contexacommon.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Collections;
import java.util.List;

/**
 * HCAD 이상 탐지 기능 설정 Properties
 *
 * 사용자 application.yml 설정 예시:
 * <pre>
 * security:
 *   anomaly-detection:
 *     enabled: true
 *     block-on-anomaly: true
 *     notification:
 *       enabled: true
 *       channels:
 *         - EMAIL
 *         - SLACK
 * </pre>
 */
@Data
@ConfigurationProperties(prefix = "security.anomaly-detection")
public class SecurityAnomalyDetectionProperties {

    /**
     * 이상 탐지 기능 활성화 여부
     * 기본값: false
     */
    private boolean enabled = false;

    /**
     * 이상 탐지 시 인증 차단 여부
     * 기본값: true (Zero Trust 철학)
     */
    private boolean blockOnAnomaly = true;

    /**
     * 알림 설정
     */
    private NotificationProperties notification = new NotificationProperties();

    @Data
    public static class NotificationProperties {
        /**
         * 알림 기능 활성화 여부
         * 기본값: false
         */
        private boolean enabled = false;

        /**
         * 알림 채널 목록
         * 가능한 값: EMAIL, SLACK, SMS, WEBHOOK
         */
        private List<String> channels = Collections.emptyList();
    }
}
