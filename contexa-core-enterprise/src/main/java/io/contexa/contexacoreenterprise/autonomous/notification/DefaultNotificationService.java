package io.contexa.contexacoreenterprise.autonomous.notification;

import io.contexa.contexacore.autonomous.notification.NotificationService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.stereotype.Service;

import java.util.Map;

/**
 * Default Notification Service Implementation
 *
 * 기본 알림 서비스 구현체입니다.
 * 실제 환경에서는 이메일, 슬랙, 웹소켓 등으로 알림을 전송합니다.
 *
 * @author contexa
 * @since 3.1.0
 */
@Slf4j
@Service
@ConditionalOnClass(name = "io.contexa.contexacore.repository.PolicyProposalRepository")
public class DefaultNotificationService implements NotificationService {

    @Override
    public void sendNotification(String type, String message, Map<String, Object> data, Priority priority) {
        // 로그로 알림 출력 (실제 환경에서는 실제 알림 시스템으로 전송)
        log.info("[NOTIFICATION] Type: {}, Priority: {}, Message: {}, Data: {}",
                 type, priority, message, data);

        // 우선순위에 따른 처리
        switch (priority) {
            case CRITICAL:
                handleCriticalNotification(type, message, data);
                break;
            case HIGH:
                handleHighPriorityNotification(type, message, data);
                break;
            case MEDIUM:
                handleMediumPriorityNotification(type, message, data);
                break;
            case LOW:
                handleLowPriorityNotification(type, message, data);
                break;
        }
    }

    private void handleCriticalNotification(String type, String message, Map<String, Object> data) {
        log.error("[CRITICAL ALERT] {}: {}", type, message);
        // 실제 환경: SMS, 전화, 즉시 이메일 등
    }

    private void handleHighPriorityNotification(String type, String message, Map<String, Object> data) {
        log.warn("[HIGH PRIORITY] {}: {}", type, message);
        // 실제 환경: 이메일, 슬랙 멘션 등
    }

    private void handleMediumPriorityNotification(String type, String message, Map<String, Object> data) {
        log.info("[MEDIUM PRIORITY] {}: {}", type, message);
        // 실제 환경: 슬랙 채널, 대시보드 알림 등
    }

    private void handleLowPriorityNotification(String type, String message, Map<String, Object> data) {
        log.debug("[LOW PRIORITY] {}: {}", type, message);
        // 실제 환경: 로그, 일일 요약 등
    }
}