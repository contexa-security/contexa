package io.contexa.contexaiam.security.xacml.pip.attribute;

import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.entity.business.BusinessResource;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacommon.repository.BusinessResourceActionRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
public class DatabaseAttributePIP implements AttributeInformationPoint {

    private final UserRepository userRepository;
    private final AuditLogRepository auditLogRepository;
    private final BusinessResourceActionRepository resourceActionRepository;

    @Override
    public Map<String, Object> getAttributes(AuthorizationContext context) {
        long startTime = System.currentTimeMillis();
        Map<String, Object> attributes = new HashMap<>();
        
        try {

            enrichBasicUserAttributes(context, attributes);

            enrichUserBehaviorMetrics(context, attributes);

            enrichResourceAccessPatterns(context, attributes);

            enrichTimeAndEnvironmentAttributes(context, attributes);

            enrichSecurityProfile(context, attributes);
            
            long processingTime = System.currentTimeMillis() - startTime;
            attributes.put("attributeCollectionTimeMs", processingTime);

            return attributes;
            
        } catch (Exception e) {
            log.error("Attribute collection failed", e);
            attributes.put("attributeCollectionError", e.getMessage());
            return attributes;
        }
    }

    private void enrichBasicUserAttributes(AuthorizationContext context, Map<String, Object> attributes) {
        if (context.subject() != null) {
            try {
                String username = context.subject().getName();
                attributes.put("username", username);
                
                Optional<Users> userOpt = userRepository.findByUsernameWithGroupsRolesAndPermissions(username);
                if (userOpt.isPresent()) {
                    Users user = userOpt.get();

                    attributes.put("userId", user.getId());
                    attributes.put("userEmail", user.getUsername());
                    attributes.put("userStatus", "ACTIVE");
                    attributes.put("createdAt", user.getCreatedAt());
                    attributes.put("updatedAt", user.getUpdatedAt());

                    if (user.getUserGroups() != null) {
                        List<String> groupNames = user.getUserGroups().stream()
                            .map(ug -> ug.getGroup().getName())
                            .collect(Collectors.toList());
                        attributes.put("userGroups", groupNames);
                        attributes.put("groupCount", groupNames.size());
                    }

                    attributes.put("mfaEnabled", user.isMfaEnabled());
                    
                                    }
            } catch (Exception e) {
                log.warn("Basic user attribute collection failed", e);
            }
        }
    }

    private void enrichUserBehaviorMetrics(AuthorizationContext context, Map<String, Object> attributes) {
        try {
            String username = (String) attributes.get("username");
            if (username == null) return;
            
            LocalDateTime now = LocalDateTime.now();
            LocalDateTime oneHourAgo = now.minusHours(1);
            LocalDateTime oneDayAgo = now.minusDays(1);
            LocalDateTime oneWeekAgo = now.minusWeeks(1);

            attributes.put("requestsInLastHour", auditLogRepository.countByPrincipalNameAndTimeRange(username, oneHourAgo, now));
            attributes.put("requestsInLastDay", auditLogRepository.countByPrincipalNameAndTimeRange(username, oneDayAgo, now));
            attributes.put("requestsInLastWeek", auditLogRepository.countByPrincipalNameAndTimeRange(username, oneWeekAgo, now));

            attributes.put("uniqueResourcesAccessed", auditLogRepository.countDistinctResourcesByPrincipalName(username));
            
            attributes.put("failedAttemptsToday", 0L);

            List<Object[]> hourData = auditLogRepository.findTypicalAccessHoursByPrincipalName(username);
            List<Integer> typicalHours = hourData.stream()
                .map(row -> (Integer) row[0])
                .limit(5)
                .collect(Collectors.toList());
            attributes.put("typicalAccessHours", typicalHours);
            attributes.put("isCurrentHourTypical", typicalHours.contains(now.getHour()));

            attributes.put("accessVelocity", calculateAccessVelocity(username));
            attributes.put("averageSessionGap", calculateAverageSessionGap(username));

        } catch (Exception e) {
            log.warn("Behavior metrics collection failed", e);
        }
    }

    private void enrichResourceAccessPatterns(AuthorizationContext context, Map<String, Object> attributes) {
        try {
            String resourceId = context.resource().identifier();
            if (resourceId == null) return;

            attributes.put("resourceTotalAccess", auditLogRepository.countByResourceIdentifier(resourceId));
            attributes.put("resourceUniqueUsers", auditLogRepository.countDistinctUsersByResourceIdentifier(resourceId));
            attributes.put("resourceRecentFailures", auditLogRepository.countFailedAttemptsSince(resourceId, LocalDateTime.now().minusHours(24)));

            Optional<BusinessResource> resourceInfo = resourceActionRepository.findByResourceIdentifier(resourceId);
            if (resourceInfo.isPresent()) {
                attributes.put("resourceExists", true);
                
                BusinessResource resource = resourceInfo.get();
                String sensitivityLevel = determineSensitivityLevel(resource.getResourceType());
                attributes.put("resourceSensitivityLevel", sensitivityLevel);
                attributes.put("resourceAllowedActions", resourceActionRepository.countActionsByResourceIdentifier(resourceId));
            } else {
                attributes.put("resourceExists", false);
                attributes.put("resourceSensitivityLevel", "UNKNOWN");
            }

        } catch (Exception e) {
            log.warn("Resource pattern analysis failed", e);
        }
    }

    private void enrichTimeAndEnvironmentAttributes(AuthorizationContext context, Map<String, Object> attributes) {
        try {
            LocalDateTime now = LocalDateTime.now();

            attributes.put("currentHour", now.getHour());
            attributes.put("currentDayOfWeek", now.getDayOfWeek().name());
            attributes.put("isBusinessHours", isBusinessHours(now));
            attributes.put("isWeekend", now.getDayOfWeek().getValue() >= 6);
            attributes.put("accessTimestamp", now.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));

            if (context.environment() != null) {
                attributes.put("remoteAddress", context.environment().remoteIp());
                attributes.put("accessTime", context.environment().timestamp());
                attributes.put("sessionId", "session-" + System.currentTimeMillis()); 
            }

        } catch (Exception e) {
            log.warn("Time/environment analysis failed", e);
        }
    }

    private void enrichSecurityProfile(AuthorizationContext context, Map<String, Object> attributes) {
        try {
            String username = (String) attributes.get("username");
            if (username == null) return;

            double securityScore = calculateSecurityScore(attributes);
            attributes.put("userSecurityScore", securityScore);

            boolean hasRecentFailures = (Long) attributes.getOrDefault("failedAttemptsToday", 0L) > 0;
            boolean highVelocity = (Double) attributes.getOrDefault("accessVelocity", 0.0) > 10.0;
            boolean unusualTime = !(Boolean) attributes.getOrDefault("isCurrentHourTypical", true);
            
            attributes.put("hasRecentFailures", hasRecentFailures);
            attributes.put("highAccessVelocity", highVelocity);
            attributes.put("unusualAccessTime", unusualTime);
            attributes.put("riskIndicatorCount", 
                (hasRecentFailures ? 1 : 0) + (highVelocity ? 1 : 0) + (unusualTime ? 1 : 0));

        } catch (Exception e) {
            log.warn("Security profile analysis failed", e);
        }
    }

    private double calculateAccessVelocity(String username) {
        try {
            LocalDateTime oneHourAgo = LocalDateTime.now().minusHours(1);
            long recentAccess = auditLogRepository.countByPrincipalNameAndTimeRange(username, oneHourAgo, LocalDateTime.now());
            return recentAccess / 60.0; 
        } catch (Exception e) {
            return 0.0;
        }
    }

    private double calculateAverageSessionGap(String username) {
        
        return 30.0; 
    }

    private boolean isBusinessHours(LocalDateTime time) {
        int hour = time.getHour();
        int dayOfWeek = time.getDayOfWeek().getValue();
        return dayOfWeek <= 5 && hour >= 9 && hour <= 18; 
    }

    private double calculateSecurityScore(Map<String, Object> attributes) {
        double score = 1.0;

        if ((Boolean) attributes.getOrDefault("mfaEnabled", false)) {
            score += 0.2;
        }

        long failedAttempts = (Long) attributes.getOrDefault("failedAttemptsToday", 0L);
        if (failedAttempts > 0) {
            score -= Math.min(0.3, failedAttempts * 0.1);
        }

        Object createdAt = attributes.get("accountCreated");
        if (createdAt instanceof LocalDateTime) {
            long daysSinceCreation = java.time.temporal.ChronoUnit.DAYS.between((LocalDateTime) createdAt, LocalDateTime.now());
            if (daysSinceCreation > 30) {
                score += 0.1; 
            }
        }
        
        return Math.max(0.0, Math.min(2.0, score));
    }

    private String determineSensitivityLevel(String resourceType) {
        if (resourceType == null) return "STANDARD";
        
        String type = resourceType.toUpperCase();
        if (type.contains("FINANCIAL") || type.contains("SENSITIVE") || type.contains("CONFIDENTIAL")) {
            return "HIGH";
        } else if (type.contains("INTERNAL") || type.contains("PROTECTED")) {
            return "MEDIUM";
        } else {
            return "STANDARD";
        }
    }
}
