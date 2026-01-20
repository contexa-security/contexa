package io.contexa.contexacoreenterprise.soar.notification;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Set;


@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class NotificationTarget {
    
    
    private String targetId;
    
    
    private TargetType targetType;
    
    
    private String name;
    
    
    private String email;
    
    
    private String phoneNumber;
    
    
    private String webSocketSessionId;
    
    
    private Set<String> roles;
    
    
    private List<NotificationChannel> preferredChannels;
    
    
    private boolean active;
    
    
    private boolean online;
    
    
    private String timezone;
    
    
    private String language;
    
    
    public enum TargetType {
        USER,           
        GROUP,          
        ROLE,           
        ESCALATION      
    }
    
    
    public enum NotificationChannel {
        EMAIL,          
        WEBSOCKET,      
        SSE,            
        SMS,            
        SLACK,          
        TEAMS           
    }
    
    
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
    
    
    public boolean supportsChannel(NotificationChannel channel) {
        return preferredChannels != null && preferredChannels.contains(channel);
    }
    
    
    public boolean canReceiveEmail() {
        return active && email != null && !email.isBlank() 
                && supportsChannel(NotificationChannel.EMAIL);
    }
    
    
    public boolean canReceiveWebSocket() {
        return active && online && webSocketSessionId != null 
                && supportsChannel(NotificationChannel.WEBSOCKET);
    }
    
    
    public boolean canReceiveSSE() {
        return active && supportsChannel(NotificationChannel.SSE);
    }
}