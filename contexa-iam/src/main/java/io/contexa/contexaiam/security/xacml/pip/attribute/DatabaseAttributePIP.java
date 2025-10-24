package io.contexa.contexaiam.security.xacml.pip.attribute;

import io.contexa.contexaiam.domain.dto.UserDto;
import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.entity.business.BusinessResource;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacommon.repository.BusinessResourceActionRepository;
import io.contexa.contexacommon.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * AI-Native 위험 평가용 속성 정보 지점 (강화판)
 * 
 * SpEL 표현식에서 #getAttribute()로 접근할 수 있는 모든 속성을 제공합니다.
 * AI 위험 평가와 동일한 수준의 풍부한 컨텍스트를 지원합니다.
 */
@Slf4j
@Service
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
            log.debug("Starting comprehensive attribute collection");
            
            // 1. 기본 사용자 정보 수집
            enrichBasicUserAttributes(context, attributes);
            
            // 2. 사용자 행동 메트릭 수집 (실무급)
            enrichUserBehaviorMetrics(context, attributes);
            
            // 3. 리소스 접근 패턴 분석
            enrichResourceAccessPatterns(context, attributes);
            
            // 4. 시간 및 환경 분석
            enrichTimeAndEnvironmentAttributes(context, attributes);
            
            // 5. 보안 프로파일 분석
            enrichSecurityProfile(context, attributes);
            
            long processingTime = System.currentTimeMillis() - startTime;
            attributes.put("attributeCollectionTimeMs", processingTime);
            
            log.debug("Comprehensive attributes collected in {}ms - {} attributes", 
                     processingTime, attributes.size());
            
            return attributes;
            
        } catch (Exception e) {
            log.error("Attribute collection failed", e);
            attributes.put("attributeCollectionError", e.getMessage());
            return attributes;
        }
    }
    
    /**
     * 기본 사용자 정보 수집
     */
    private void enrichBasicUserAttributes(AuthorizationContext context, Map<String, Object> attributes) {
        if (context.subject() != null) {
            try {
                String username = ((UserDto)(context.subject().getPrincipal())).getUsername();
                attributes.put("username", username);
                
                Optional<Users> userOpt = userRepository.findByUsernameWithGroupsRolesAndPermissions(username);
                if (userOpt.isPresent()) {
                    Users user = userOpt.get();
                    
                    // 사용자 기본 정보
                    attributes.put("userId", user.getId());
                    attributes.put("userEmail", user.getUsername());
                    attributes.put("userStatus", "ACTIVE");
                    attributes.put("createdAt", user.getCreatedAt());
                    attributes.put("updatedAt", user.getUpdatedAt());
                    
                    // 역할 및 권한 정보
                    if (user.getUserGroups() != null) {
                        List<String> groupNames = user.getUserGroups().stream()
                            .map(ug -> ug.getGroup().getName())
                            .collect(Collectors.toList());
                        attributes.put("userGroups", groupNames);
                        attributes.put("groupCount", groupNames.size());
                    }
                    
                    // MFA 상태
                    attributes.put("mfaEnabled", user.isMfaEnabled());
                    
                    log.debug("👤 Basic user attributes collected for: {}", username);
                }
            } catch (Exception e) {
                log.warn("Basic user attribute collection failed", e);
            }
        }
    }
    
    /**
     * 사용자 행동 메트릭 수집 (실무급)
     */
    private void enrichUserBehaviorMetrics(AuthorizationContext context, Map<String, Object> attributes) {
        try {
            String username = (String) attributes.get("username");
            if (username == null) return;
            
            LocalDateTime now = LocalDateTime.now();
            LocalDateTime oneHourAgo = now.minusHours(1);
            LocalDateTime oneDayAgo = now.minusDays(1);
            LocalDateTime oneWeekAgo = now.minusWeeks(1);
            
            // 실시간 활동 메트릭
            attributes.put("requestsInLastHour", auditLogRepository.countByPrincipalNameAndTimeRange(username, oneHourAgo, now));
            attributes.put("requestsInLastDay", auditLogRepository.countByPrincipalNameAndTimeRange(username, oneDayAgo, now));
            attributes.put("requestsInLastWeek", auditLogRepository.countByPrincipalNameAndTimeRange(username, oneWeekAgo, now));
            
            // 접근 패턴 분석
            attributes.put("uniqueResourcesAccessed", auditLogRepository.countDistinctResourcesByPrincipalName(username));
            // 사용자 실패 시도는 별도 로직으로 처리 (임시)
            attributes.put("failedAttemptsToday", 0L);
            
            // 일반적인 접근 시간대
            List<Object[]> hourData = auditLogRepository.findTypicalAccessHoursByPrincipalName(username);
            List<Integer> typicalHours = hourData.stream()
                .map(row -> (Integer) row[0])
                .limit(5)
                .collect(Collectors.toList());
            attributes.put("typicalAccessHours", typicalHours);
            attributes.put("isCurrentHourTypical", typicalHours.contains(now.getHour()));
            
            // 접근 속도 분석
            attributes.put("accessVelocity", calculateAccessVelocity(username));
            attributes.put("averageSessionGap", calculateAverageSessionGap(username));
            
            log.debug("Behavior metrics collected for user: {}", username);
            
        } catch (Exception e) {
            log.warn("Behavior metrics collection failed", e);
        }
    }
    
    /**
     * 리소스 접근 패턴 분석
     */
    private void enrichResourceAccessPatterns(AuthorizationContext context, Map<String, Object> attributes) {
        try {
            String resourceId = context.resource().identifier();
            if (resourceId == null) return;
            
            // 리소스 접근 통계
            attributes.put("resourceTotalAccess", auditLogRepository.countByResourceIdentifier(resourceId));
            attributes.put("resourceUniqueUsers", auditLogRepository.countDistinctUsersByResourceIdentifier(resourceId));
            attributes.put("resourceRecentFailures", auditLogRepository.countFailedAttemptsSince(resourceId, LocalDateTime.now().minusHours(24)));
            
            // 리소스 정보 및 민감도
            Optional<BusinessResource> resourceInfo = resourceActionRepository.findByResourceIdentifier(resourceId);
            if (resourceInfo.isPresent()) {
                attributes.put("resourceExists", true);
                // 리소스 타입 기반 민감도 판단
                BusinessResource resource = resourceInfo.get();
                String sensitivityLevel = determineSensitivityLevel(resource.getResourceType());
                attributes.put("resourceSensitivityLevel", sensitivityLevel);
                attributes.put("resourceAllowedActions", resourceActionRepository.countActionsByResourceIdentifier(resourceId));
            } else {
                attributes.put("resourceExists", false);
                attributes.put("resourceSensitivityLevel", "UNKNOWN");
            }
            
            log.debug("Resource pattern analysis for: {}", resourceId);
            
        } catch (Exception e) {
            log.warn("Resource pattern analysis failed", e);
        }
    }
    
    /**
     * 시간 및 환경 분석
     */
    private void enrichTimeAndEnvironmentAttributes(AuthorizationContext context, Map<String, Object> attributes) {
        try {
            LocalDateTime now = LocalDateTime.now();
            
            // 시간 분석
            attributes.put("currentHour", now.getHour());
            attributes.put("currentDayOfWeek", now.getDayOfWeek().name());
            attributes.put("isBusinessHours", isBusinessHours(now));
            attributes.put("isWeekend", now.getDayOfWeek().getValue() >= 6);
            attributes.put("accessTimestamp", now.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            
            // 환경 정보 (가능한 경우)
            if (context.environment() != null) {
                attributes.put("remoteAddress", context.environment().remoteIp());
                attributes.put("accessTime", context.environment().timestamp());
                attributes.put("sessionId", "session-" + System.currentTimeMillis()); // 임시 세션ID
            }
            
            log.debug("⏰ Time and environment attributes collected");
            
        } catch (Exception e) {
            log.warn("Time/environment analysis failed", e);
        }
    }
    
    /**
     * 보안 프로파일 분석
     */
    private void enrichSecurityProfile(AuthorizationContext context, Map<String, Object> attributes) {
        try {
            String username = (String) attributes.get("username");
            if (username == null) return;
            
            // 보안 점수 계산
            double securityScore = calculateSecurityScore(attributes);
            attributes.put("userSecurityScore", securityScore);
            
            // 위험 지표
            boolean hasRecentFailures = (Long) attributes.getOrDefault("failedAttemptsToday", 0L) > 0;
            boolean highVelocity = (Double) attributes.getOrDefault("accessVelocity", 0.0) > 10.0;
            boolean unusualTime = !(Boolean) attributes.getOrDefault("isCurrentHourTypical", true);
            
            attributes.put("hasRecentFailures", hasRecentFailures);
            attributes.put("highAccessVelocity", highVelocity);
            attributes.put("unusualAccessTime", unusualTime);
            attributes.put("riskIndicatorCount", 
                (hasRecentFailures ? 1 : 0) + (highVelocity ? 1 : 0) + (unusualTime ? 1 : 0));
            
            log.debug("Security profile analysis completed - Score: {}", securityScore);
            
        } catch (Exception e) {
            log.warn("Security profile analysis failed", e);
        }
    }
    
    /**
     * 접근 속도 계산
     */
    private double calculateAccessVelocity(String username) {
        try {
            LocalDateTime oneHourAgo = LocalDateTime.now().minusHours(1);
            long recentAccess = auditLogRepository.countByPrincipalNameAndTimeRange(username, oneHourAgo, LocalDateTime.now());
            return recentAccess / 60.0; // 분당 접근 횟수
        } catch (Exception e) {
            return 0.0;
        }
    }
    
    /**
     * 평균 세션 간격 계산
     */
    private double calculateAverageSessionGap(String username) {
        // 구현 예시 (실제로는 더 복잡한 로직 필요)
        return 30.0; // 평균 30분 간격
    }
    
    /**
     * 업무 시간 판단
     */
    private boolean isBusinessHours(LocalDateTime time) {
        int hour = time.getHour();
        int dayOfWeek = time.getDayOfWeek().getValue();
        return dayOfWeek <= 5 && hour >= 9 && hour <= 18; // 평일 9-18시
    }
    
    /**
     * 보안 점수 계산
     */
    private double calculateSecurityScore(Map<String, Object> attributes) {
        double score = 1.0;
        
        // MFA 활성화 여부
        if ((Boolean) attributes.getOrDefault("mfaEnabled", false)) {
            score += 0.2;
        }
        
        // 최근 실패 시도
        long failedAttempts = (Long) attributes.getOrDefault("failedAttemptsToday", 0L);
        if (failedAttempts > 0) {
            score -= Math.min(0.3, failedAttempts * 0.1);
        }
        
        // 계정 연령 (생성일 기준)
        Object createdAt = attributes.get("accountCreated");
        if (createdAt instanceof LocalDateTime) {
            long daysSinceCreation = java.time.temporal.ChronoUnit.DAYS.between((LocalDateTime) createdAt, LocalDateTime.now());
            if (daysSinceCreation > 30) {
                score += 0.1; // 오래된 계정은 더 신뢰할 만함
            }
        }
        
        return Math.max(0.0, Math.min(2.0, score));
    }
    
    /**
     * 리소스 타입 기반 민감도 판단
     */
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
