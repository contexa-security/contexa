package io.contexa.contexacoreenterprise.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.retry.annotation.EnableRetry;
import org.springframework.scheduling.annotation.EnableAsync;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.templatemode.TemplateMode;
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver;

import java.util.Properties;

/**
 * 알림 시스템 설정
 * 이메일, WebSocket, SSE 등 다중 채널 알림을 위한 설정
 */
@Configuration
@EnableRetry
public class NotificationConfig {
    
    /**
     * JavaMailSender 빈 설정
     * application.yml의 메일 설정을 사용하여 자동 구성됨
     */
    @Bean
    @ConditionalOnProperty(name = "soar.notification.email.enabled", havingValue = "true", matchIfMissing = true)
    public JavaMailSender javaMailSender() {
        JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
        
        // Spring Boot의 자동 구성을 사용하지만, 필요시 여기서 커스터마이징 가능
        // 실제 값은 application.yml에서 주입됨
        
        return mailSender;
    }
    
    /**
     * 이메일 템플릿 엔진 설정
     */
    @Bean
    public TemplateEngine emailTemplateEngine() {
        SpringTemplateEngine templateEngine = new SpringTemplateEngine();
        templateEngine.addTemplateResolver(emailTemplateResolver());
        return templateEngine;
    }
    
    /**
     * 이메일 템플릿 리졸버
     */
    private ClassLoaderTemplateResolver emailTemplateResolver() {
        ClassLoaderTemplateResolver templateResolver = new ClassLoaderTemplateResolver();
        templateResolver.setPrefix("templates/");
        templateResolver.setSuffix(".html");
        templateResolver.setTemplateMode(TemplateMode.HTML);
        templateResolver.setCharacterEncoding("UTF-8");
        templateResolver.setCacheable(false); // 개발 중에는 캐시 비활성화
        templateResolver.setOrder(1);
        return templateResolver;
    }
    
    /**
     * 알림 타겟 관리자
     * 사용자별 알림 채널 선호도와 연결 상태를 관리
     */
    @Bean
    public NotificationTargetManager notificationTargetManager() {
        return new NotificationTargetManager();
    }
    
    /**
     * 알림 타겟 관리자 클래스
     */
    public static class NotificationTargetManager {
        private final java.util.Map<String, io.contexa.contexacoreenterprise.soar.notification.NotificationTarget> targets =
            new java.util.concurrent.ConcurrentHashMap<>();

        /**
         * 타겟 등록
         */
        public void registerTarget(io.contexa.contexacoreenterprise.soar.notification.NotificationTarget target) {
            targets.put(target.getTargetId(), target);
        }

        /**
         * 타겟 조회
         */
        public io.contexa.contexacoreenterprise.soar.notification.NotificationTarget getTarget(String targetId) {
            return targets.get(targetId);
        }

        /**
         * 역할별 타겟 조회
         */
        public java.util.List<io.contexa.contexacoreenterprise.soar.notification.NotificationTarget> getTargetsByRole(String role) {
            return targets.values().stream()
                    .filter(t -> t.getRoles() != null && t.getRoles().contains(role))
                    .toList();
        }

        /**
         * 온라인 타겟 조회
         */
        public java.util.List<io.contexa.contexacoreenterprise.soar.notification.NotificationTarget> getOnlineTargets() {
            return targets.values().stream()
                    .filter(io.contexa.contexacoreenterprise.soar.notification.NotificationTarget::isOnline)
                    .toList();
        }

        /**
         * WebSocket 세션 업데이트
         */
        public void updateWebSocketSession(String targetId, String sessionId, boolean online) {
            io.contexa.contexacoreenterprise.soar.notification.NotificationTarget target = targets.get(targetId);
            if (target != null) {
                target.setWebSocketSessionId(sessionId);
                target.setOnline(online);
            }
        }
        
        /**
         * 기본 관리자 타겟 생성
         */
        public void initializeDefaultTargets() {
            // 기본 관리자 타겟
            io.contexa.contexacoreenterprise.soar.notification.NotificationTarget adminTarget =
                io.contexa.contexacoreenterprise.soar.notification.NotificationTarget.createDefault(
                    "admin",
                    "System Administrator",
                    "admin@contexa.com"
                );
            adminTarget.setRoles(java.util.Set.of("ROLE_ADMIN", "ROLE_APPROVER"));
            registerTarget(adminTarget);

            // 보안 팀 타겟
            io.contexa.contexacoreenterprise.soar.notification.NotificationTarget securityTarget =
                io.contexa.contexacoreenterprise.soar.notification.NotificationTarget.createForRole("ROLE_SECURITY");
            securityTarget.setEmail("security-team@contexa.com");
            registerTarget(securityTarget);

            // SOC 팀 타겟
            io.contexa.contexacoreenterprise.soar.notification.NotificationTarget socTarget =
                io.contexa.contexacoreenterprise.soar.notification.NotificationTarget.createForRole("ROLE_SOC");
            socTarget.setEmail("soc-team@contexa.com");
            registerTarget(socTarget);
        }
    }
}