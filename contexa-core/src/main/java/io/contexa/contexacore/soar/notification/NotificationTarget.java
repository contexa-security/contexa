package io.contexa.contexacore.soar.notification;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Set;

/**
 * 알림 대상 정보
 * 승인 알림을 받을 사용자 또는 그룹의 정보를 담습니다.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class NotificationTarget {
    
    /**
     * 대상 ID (사용자 ID 또는 그룹 ID)
     */
    private String targetId;
    
    /**
     * 대상 유형
     */
    private TargetType targetType;
    
    /**
     * 대상 이름
     */
    private String name;
    
    /**
     * 이메일 주소
     */
    private String email;
    
    /**
     * 전화번호 (SMS 알림용)
     */
    private String phoneNumber;
    
    /**
     * WebSocket 세션 ID
     */
    private String webSocketSessionId;
    
    /**
     * 역할 목록
     */
    private Set<String> roles;
    
    /**
     * 알림 채널 선호도
     */
    private List<NotificationChannel> preferredChannels;
    
    /**
     * 활성 상태
     */
    private boolean active;
    
    /**
     * 온라인 상태 (WebSocket 연결 상태)
     */
    private boolean online;
    
    /**
     * 시간대 (알림 스케줄링용)
     */
    private String timezone;
    
    /**
     * 언어 설정
     */
    private String language;
    
    /**
     * 대상 유형
     */
    public enum TargetType {
        USER,           // 개별 사용자
        GROUP,          // 그룹
        ROLE,           // 역할 기반
        ESCALATION      // 에스컬레이션 대상
    }
    
    /**
     * 알림 채널
     */
    public enum NotificationChannel {
        EMAIL,          // 이메일
        WEBSOCKET,      // WebSocket 실시간
        SSE,            // Server-Sent Events
        SMS,            // SMS (미구현)
        SLACK,          // Slack (미구현)
        TEAMS           // MS Teams (미구현)
    }
    
    /**
     * 기본 알림 대상 생성 (이메일 + WebSocket)
     */
    public static NotificationTarget createDefault(String userId, String name, String email) {
        return NotificationTarget.builder()
                .targetId(userId)
                .targetType(TargetType.USER)
                .name(name)
                .email(email)
                .preferredChannels(List.of(NotificationChannel.EMAIL, NotificationChannel.WEBSOCKET))
                .active(true)
                .online(false)
                .language("ko")
                .timezone("Asia/Seoul")
                .build();
    }
    
    /**
     * 역할 기반 알림 대상 생성
     */
    public static NotificationTarget createForRole(String roleName) {
        return NotificationTarget.builder()
                .targetId("ROLE_" + roleName)
                .targetType(TargetType.ROLE)
                .name(roleName + " Role Group")
                .roles(Set.of(roleName))
                .preferredChannels(List.of(NotificationChannel.WEBSOCKET, NotificationChannel.EMAIL))
                .active(true)
                .build();
    }
    
    /**
     * 특정 채널 지원 여부 확인
     */
    public boolean supportsChannel(NotificationChannel channel) {
        return preferredChannels != null && preferredChannels.contains(channel);
    }
    
    /**
     * 이메일 알림 가능 여부
     */
    public boolean canReceiveEmail() {
        return active && email != null && !email.isBlank() 
                && supportsChannel(NotificationChannel.EMAIL);
    }
    
    /**
     * WebSocket 알림 가능 여부
     */
    public boolean canReceiveWebSocket() {
        return active && online && webSocketSessionId != null 
                && supportsChannel(NotificationChannel.WEBSOCKET);
    }
    
    /**
     * SSE 알림 가능 여부
     */
    public boolean canReceiveSSE() {
        return active && supportsChannel(NotificationChannel.SSE);
    }
}