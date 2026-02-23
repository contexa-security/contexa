package io.contexa.contexacoreenterprise.soar.notification;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Registry for notification targets. Manages notification recipient lookup
 * by ID, role, and online status for multi-channel notification routing.
 */
public class NotificationTargetManager {

    private final Map<String, NotificationTarget> targets = new ConcurrentHashMap<>();

    public void registerTarget(NotificationTarget target) {
        targets.put(target.getTargetId(), target);
    }

    public NotificationTarget getTarget(String targetId) {
        return targets.get(targetId);
    }

    public List<NotificationTarget> getTargetsByRole(String role) {
        return targets.values().stream()
                .filter(t -> t.getRoles() != null && t.getRoles().contains(role))
                .toList();
    }

    public void initializeDefaultTargets() {
        NotificationTarget adminTarget = NotificationTarget.createDefault(
                "admin", "System Administrator", "admin@contexa.com");
        adminTarget.setRoles(Set.of("ROLE_ADMIN", "ROLE_APPROVER"));
        registerTarget(adminTarget);

        NotificationTarget securityTarget = NotificationTarget.createForRole("ROLE_SECURITY");
        securityTarget.setEmail("security-team@contexa.com");
        registerTarget(securityTarget);

        NotificationTarget socTarget = NotificationTarget.createForRole("ROLE_SOC");
        socTarget.setEmail("soc-team@contexa.com");
        registerTarget(socTarget);
    }
}
