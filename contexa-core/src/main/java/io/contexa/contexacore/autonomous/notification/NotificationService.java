package io.contexa.contexacore.autonomous.notification;

import java.util.Map;

/**
 * Notification Service Interface
 *
 * 보안 이벤트 및 정책 변경 사항에 대한 알림을 처리하는 서비스 인터페이스입니다.
 *
 * @author AI3Security
 * @since 3.1.0
 */
public interface NotificationService {

    /**
     * 알림 우선순위
     */
    enum Priority {
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }

    /**
     * 알림 전송
     *
     * @param type 알림 타입
     * @param message 알림 메시지
     * @param data 추가 데이터
     * @param priority 우선순위
     */
    void sendNotification(String type, String message, Map<String, Object> data, Priority priority);

    /**
     * 비동기 알림 전송
     *
     * @param type 알림 타입
     * @param message 알림 메시지
     * @param data 추가 데이터
     * @param priority 우선순위
     */
    default void sendNotificationAsync(String type, String message, Map<String, Object> data, Priority priority) {
        // 비동기 처리를 위한 기본 구현
        sendNotification(type, message, data, priority);
    }
}