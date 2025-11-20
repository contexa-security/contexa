package io.contexa.contexacore.autonomous.notification;

/**
 * SOAR Approval Notifier Interface
 *
 * <p>
 * Redis 메시지를 수신하여 SOAR 승인 알림을 처리하는 인터페이스입니다.
 * Enterprise 모듈에서 구현체를 제공하며, Core 모듈에서는 이 인터페이스를 통해 사용합니다.
 * </p>
 *
 * <p>
 * Spring Boot AutoConfiguration을 통해 Enterprise 구현체가 자동 주입됩니다.
 * </p>
 *
 * @since 0.1.1
 */
public interface SoarApprovalNotifier {

    /**
     * Redis 메시지를 수신하여 SOAR 승인 알림 처리
     *
     * @param message Redis 채널에서 수신한 승인 알림 메시지
     */
    void receiveApprovalNotification(String message);

    /**
     * 승인 대기 중인 요청에 대해 재알림 전송
     *
     * @param approvalId 승인 요청 ID
     */
    void sendApprovalReminder(String approvalId);
}
