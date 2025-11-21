package io.contexa.contexacoreenterprise.tool.authorization;

import io.contexa.contexacoreenterprise.mcp.tool.execution.ToolExecutor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * ToolAuthorizationService
 * 
 * 도구 실행 권한을 관리하는 서비스입니다.
 * 사용자, 역할, 정책 기반으로 도구 실행 권한을 확인합니다.
 */
@Slf4j
public class ToolAuthorizationService {
    
    // 사용자별 권한 캐시
    private final Map<String, Set<String>> userPermissions = new ConcurrentHashMap<>();
    
    // 역할별 권한 매핑
    private final Map<String, Set<String>> rolePermissions = new ConcurrentHashMap<>();
    
    // 도구별 필요 권한
    private final Map<String, Set<String>> toolRequiredPermissions = new ConcurrentHashMap<>();
    
    // 승인 요청 저장소
    private final Map<String, ToolExecutor.ApprovalRequest> pendingApprovals = new ConcurrentHashMap<>();
    
    public ToolAuthorizationService() {
        initializeDefaultPermissions();
    }
    
    /**
     * 도구 실행 권한 확인
     */
    public Optional<Boolean> authorize(ToolCallback tool, ToolExecutor.ExecutionContext context) {
        String toolName = tool.getToolDefinition().name();
        String userId = context.getUserId();
        
        log.debug("권한 확인: user={}, tool={}", userId, toolName);
        
        // 1. 사용자 권한 확인
        Set<String> userPerms = getUserPermissions(userId);
        Set<String> requiredPerms = getToolRequiredPermissions(toolName);
        
        // 2. 권한 매칭
        boolean hasPermission = userPerms.containsAll(requiredPerms);
        
        // 3. 추가 정책 확인
        if (hasPermission) {
            hasPermission = checkAdditionalPolicies(tool, context);
        }
        
        if (hasPermission) {
            log.debug("권한 승인: user={}, tool={}", userId, toolName);
            return Optional.of(true);
        } else {
            log.warn("권한 거부: user={}, tool={}, required={}, user_has={}", 
                userId, toolName, requiredPerms, userPerms);
            return Optional.empty();
        }
    }
    
    /**
     * 승인 요청
     */
    public boolean requestApproval(ToolExecutor.ApprovalRequest request) {
        String approvalId = generateApprovalId(request);
        
        log.info("승인 요청 생성: id={}, tool={}, user={}", 
            approvalId, request.getToolName(), request.getContext().getUserId());
        
        // 승인 요청 저장
        pendingApprovals.put(approvalId, request);
        
        // 승인 프로세스 시작 (실제로는 비동기/이벤트 기반)
        boolean approved = processApproval(request);
        
        // 승인 결과 업데이트
        request.setApproved(approved);
        if (approved) {
            request.setApprover("system_auto_approval"); // 실제로는 승인자 정보
            request.setReason("자동 승인 정책에 의해 승인됨");
        } else {
            request.setReason("보안 정책 위반");
        }
        
        // 완료된 승인 제거
        pendingApprovals.remove(approvalId);
        
        return approved;
    }
    
    /**
     * 사용자 권한 가져오기
     */
    public Set<String> getUserPermissions(String userId) {
        return userPermissions.computeIfAbsent(userId, this::loadUserPermissions);
    }
    
    /**
     * 역할 권한 가져오기
     */
    public Set<String> getRolePermissions(String role) {
        return rolePermissions.getOrDefault(role, Collections.emptySet());
    }
    
    /**
     * 도구 필요 권한 가져오기
     */
    public Set<String> getToolRequiredPermissions(String toolName) {
        return toolRequiredPermissions.computeIfAbsent(toolName, this::determineToolPermissions);
    }
    
    /**
     * 사용자 권한 부여
     */
    public void grantPermission(String userId, String permission) {
        getUserPermissions(userId).add(permission);
        log.info("권한 부여: user={}, permission={}", userId, permission);
    }
    
    /**
     * 사용자 권한 철회
     */
    public void revokePermission(String userId, String permission) {
        getUserPermissions(userId).remove(permission);
        log.info("권한 철회: user={}, permission={}", userId, permission);
    }
    
    /**
     * 역할 권한 설정
     */
    public void setRolePermissions(String role, Set<String> permissions) {
        rolePermissions.put(role, new HashSet<>(permissions));
        log.info("역할 권한 설정: role={}, permissions={}", role, permissions);
    }
    
    /**
     * 도구 필요 권한 설정
     */
    public void setToolRequiredPermissions(String toolName, Set<String> permissions) {
        toolRequiredPermissions.put(toolName, new HashSet<>(permissions));
        log.info("도구 필요 권한 설정: tool={}, permissions={}", toolName, permissions);
    }
    
    // Private 메서드들
    
    /**
     * 기본 권한 초기화
     */
    private void initializeDefaultPermissions() {
        // 역할별 기본 권한
        rolePermissions.put("ADMIN", Set.of(
            "tool.execute.all",
            "tool.approve.all",
            "system.manage"
        ));
        
        rolePermissions.put("OPERATOR", Set.of(
            "tool.execute.read",
            "tool.execute.analysis",
            "tool.execute.report"
        ));
        
        rolePermissions.put("VIEWER", Set.of(
            "tool.execute.read",
            "tool.view.results"
        ));
        
        // 도구별 기본 필요 권한
        toolRequiredPermissions.put("network_scan", Set.of(
            "tool.execute.scan",
            "network.access"
        ));
        
        toolRequiredPermissions.put("log_analysis", Set.of(
            "tool.execute.analysis",
            "log.read"
        ));
        
        toolRequiredPermissions.put("file_quarantine", Set.of(
            "tool.execute.quarantine",
            "file.modify",
            "security.high"
        ));
        
        log.info("기본 권한 설정 완료: {} 개 역할, {} 개 도구", 
            rolePermissions.size(), toolRequiredPermissions.size());
    }
    
    /**
     * 사용자 권한 로드
     */
    private Set<String> loadUserPermissions(String userId) {
        // 실제로는 데이터베이스나 외부 시스템에서 로드
        Set<String> permissions = new HashSet<>();
        
        // 기본 권한 부여 (데모용)
        if ("admin".equals(userId)) {
            permissions.addAll(rolePermissions.get("ADMIN"));
        } else {
            permissions.addAll(rolePermissions.get("OPERATOR"));
        }
        
        log.debug("사용자 권한 로드: user={}, permissions={}", userId, permissions);
        return permissions;
    }
    
    /**
     * 도구 권한 결정
     */
    private Set<String> determineToolPermissions(String toolName) {
        Set<String> permissions = new HashSet<>();
        
        // 도구 이름 기반 권한 추론
        if (toolName.contains("scan") || toolName.contains("probe")) {
            permissions.add("tool.execute.scan");
        }
        
        if (toolName.contains("analysis") || toolName.contains("analyze")) {
            permissions.add("tool.execute.analysis");
        }
        
        if (toolName.contains("delete") || toolName.contains("remove") || 
            toolName.contains("quarantine")) {
            permissions.add("tool.execute.modify");
            permissions.add("security.high");
        }
        
        // 기본 권한
        permissions.add("tool.execute.basic");
        
        return permissions;
    }
    
    /**
     * 추가 정책 확인
     */
    private boolean checkAdditionalPolicies(ToolCallback tool, ToolExecutor.ExecutionContext context) {
        // 운영 환경에서 위험한 도구 차단
        if (context.isProductionEnvironment()) {
            String toolName = tool.getToolDefinition().name();
            if (toolName.contains("delete") || toolName.contains("kill") || 
                toolName.contains("shutdown")) {
                log.warn("운영 환경에서 위험한 도구 차단: {}", toolName);
                return false;
            }
        }
        
        // 시간 기반 정책 (예: 업무 시간 외 제한)
        int hour = Calendar.getInstance().get(Calendar.HOUR_OF_DAY);
        if (hour < 6 || hour > 22) {
            String toolName = tool.getToolDefinition().name();
            if (toolName.contains("critical") || toolName.contains("production")) {
                log.warn("업무 시간 외 중요 도구 차단: {}", toolName);
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * 승인 처리
     */
    private boolean processApproval(ToolExecutor.ApprovalRequest request) {
        // 실제로는 승인 워크플로우 실행
        // 여기서는 간단한 자동 승인 로직
        
        String toolName = request.getToolName();
        String userId = request.getContext().getUserId();
        
        // 관리자는 자동 승인
        if (getUserPermissions(userId).contains("tool.approve.all")) {
            return true;
        }
        
        // 읽기 전용 도구는 자동 승인
        if (toolName.contains("read") || toolName.contains("view") || 
            toolName.contains("list")) {
            return true;
        }
        
        // 그 외는 거부
        return false;
    }
    
    /**
     * 승인 ID 생성
     */
    private String generateApprovalId(ToolExecutor.ApprovalRequest request) {
        return String.format("%s-%s-%d", 
            request.getToolName(),
            request.getContext().getUserId(),
            System.currentTimeMillis());
    }
    
    /**
     * 통계 정보
     */
    public Map<String, Object> getStatistics() {
        return Map.of(
            "userCount", userPermissions.size(),
            "roleCount", rolePermissions.size(),
            "toolCount", toolRequiredPermissions.size(),
            "pendingApprovals", pendingApprovals.size()
        );
    }
    
    /**
     * 관리자 권한 확인
     */
    public boolean hasAdminPrivileges(String userId) {
        if (userId == null) {
            return false;
        }
        
        // 관리자 권한 확인
        Set<String> userPerms = getUserPermissions(userId);
        
        // ADMIN 역할이 있거나 security.admin 권한이 있는지 확인
        return "admin".equalsIgnoreCase(userId) || 
               userPerms.contains("security.admin") || 
               userPerms.containsAll(rolePermissions.getOrDefault("ADMIN", Collections.emptySet()));
    }
}