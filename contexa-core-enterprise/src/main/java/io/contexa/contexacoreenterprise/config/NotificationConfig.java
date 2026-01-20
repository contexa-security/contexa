package io.contexa.contexacoreenterprise.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
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


@Configuration
@EnableRetry
@ConditionalOnClass(name = "io.contexa.contexacoreenterprise.soar.notification.NotificationTarget")
@ConditionalOnProperty(
    prefix = "contexa.enterprise",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = false
)
public class NotificationConfig {
    
    
    @Bean
    @ConditionalOnProperty(name = "soar.notification.email.enabled", havingValue = "true", matchIfMissing = true)
    public JavaMailSender javaMailSender() {
        JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
        
        
        
        
        return mailSender;
    }
    
    
    @Bean
    public TemplateEngine emailTemplateEngine() {
        SpringTemplateEngine templateEngine = new SpringTemplateEngine();
        templateEngine.addTemplateResolver(emailTemplateResolver());
        return templateEngine;
    }
    
    
    private ClassLoaderTemplateResolver emailTemplateResolver() {
        ClassLoaderTemplateResolver templateResolver = new ClassLoaderTemplateResolver();
        templateResolver.setPrefix("templates/");
        templateResolver.setSuffix(".html");
        templateResolver.setTemplateMode(TemplateMode.HTML);
        templateResolver.setCharacterEncoding("UTF-8");
        templateResolver.setCacheable(false); 
        templateResolver.setOrder(1);
        return templateResolver;
    }
    
    
    @Bean
    public NotificationTargetManager notificationTargetManager() {
        return new NotificationTargetManager();
    }
    
    
    public static class NotificationTargetManager {
        private final java.util.Map<String, io.contexa.contexacoreenterprise.soar.notification.NotificationTarget> targets =
            new java.util.concurrent.ConcurrentHashMap<>();

        
        public void registerTarget(io.contexa.contexacoreenterprise.soar.notification.NotificationTarget target) {
            targets.put(target.getTargetId(), target);
        }

        
        public io.contexa.contexacoreenterprise.soar.notification.NotificationTarget getTarget(String targetId) {
            return targets.get(targetId);
        }

        
        public java.util.List<io.contexa.contexacoreenterprise.soar.notification.NotificationTarget> getTargetsByRole(String role) {
            return targets.values().stream()
                    .filter(t -> t.getRoles() != null && t.getRoles().contains(role))
                    .toList();
        }

        
        public java.util.List<io.contexa.contexacoreenterprise.soar.notification.NotificationTarget> getOnlineTargets() {
            return targets.values().stream()
                    .filter(io.contexa.contexacoreenterprise.soar.notification.NotificationTarget::isOnline)
                    .toList();
        }

        
        public void updateWebSocketSession(String targetId, String sessionId, boolean online) {
            io.contexa.contexacoreenterprise.soar.notification.NotificationTarget target = targets.get(targetId);
            if (target != null) {
                target.setWebSocketSessionId(sessionId);
                target.setOnline(online);
            }
        }
        
        
        public void initializeDefaultTargets() {
            
            io.contexa.contexacoreenterprise.soar.notification.NotificationTarget adminTarget =
                io.contexa.contexacoreenterprise.soar.notification.NotificationTarget.createDefault(
                    "admin",
                    "System Administrator",
                    "admin@contexa.com"
                );
            adminTarget.setRoles(java.util.Set.of("ROLE_ADMIN", "ROLE_APPROVER"));
            registerTarget(adminTarget);

            
            io.contexa.contexacoreenterprise.soar.notification.NotificationTarget securityTarget =
                io.contexa.contexacoreenterprise.soar.notification.NotificationTarget.createForRole("ROLE_SECURITY");
            securityTarget.setEmail("security-team@contexa.com");
            registerTarget(securityTarget);

            
            io.contexa.contexacoreenterprise.soar.notification.NotificationTarget socTarget =
                io.contexa.contexacoreenterprise.soar.notification.NotificationTarget.createForRole("ROLE_SOC");
            socTarget.setEmail("soc-team@contexa.com");
            registerTarget(socTarget);
        }
    }
}