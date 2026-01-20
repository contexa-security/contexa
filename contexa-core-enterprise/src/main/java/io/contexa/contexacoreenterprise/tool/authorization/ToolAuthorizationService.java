package io.contexa.contexacoreenterprise.tool.authorization;

import io.contexa.contexacoreenterprise.mcp.tool.execution.ToolExecutor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;


@Slf4j
public class ToolAuthorizationService {
    
    
    private final Map<String, Set<String>> userPermissions = new ConcurrentHashMap<>();
    
    
    private final Map<String, Set<String>> rolePermissions = new ConcurrentHashMap<>();
    
    
    private final Map<String, Set<String>> toolRequiredPermissions = new ConcurrentHashMap<>();
    
    
    private final Map<String, ToolExecutor.ApprovalRequest> pendingApprovals = new ConcurrentHashMap<>();
    
    public ToolAuthorizationService() {
        initializeDefaultPermissions();
    }
    
    
    public Optional<Boolean> authorize(ToolCallback tool, ToolExecutor.ExecutionContext context) {
        String toolName = tool.getToolDefinition().name();
        String userId = context.getUserId();
        
        log.debug("권한 확인: user={}, tool={}", userId, toolName);
        
        
        Set<String> userPerms = getUserPermissions(userId);
        Set<String> requiredPerms = getToolRequiredPermissions(toolName);
        
        
        boolean hasPermission = userPerms.containsAll(requiredPerms);
        
        
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
    
    
    public boolean requestApproval(ToolExecutor.ApprovalRequest request) {
        String approvalId = generateApprovalId(request);
        
        log.info("승인 요청 생성: id={}, tool={}, user={}", 
            approvalId, request.getToolName(), request.getContext().getUserId());
        
        
        pendingApprovals.put(approvalId, request);
        
        
        boolean approved = processApproval(request);
        
        
        request.setApproved(approved);
        if (approved) {
            request.setApprover("system_auto_approval"); 
            request.setReason("자동 승인 정책에 의해 승인됨");
        } else {
            request.setReason("보안 정책 위반");
        }
        
        
        pendingApprovals.remove(approvalId);
        
        return approved;
    }
    
    
    public Set<String> getUserPermissions(String userId) {
        return userPermissions.computeIfAbsent(userId, this::loadUserPermissions);
    }
    
    
    public Set<String> getRolePermissions(String role) {
        return rolePermissions.getOrDefault(role, Collections.emptySet());
    }
    
    
    public Set<String> getToolRequiredPermissions(String toolName) {
        return toolRequiredPermissions.computeIfAbsent(toolName, this::determineToolPermissions);
    }
    
    
    public void grantPermission(String userId, String permission) {
        getUserPermissions(userId).add(permission);
        log.info("권한 부여: user={}, permission={}", userId, permission);
    }
    
    
    public void revokePermission(String userId, String permission) {
        getUserPermissions(userId).remove(permission);
        log.info("권한 철회: user={}, permission={}", userId, permission);
    }
    
    
    public void setRolePermissions(String role, Set<String> permissions) {
        rolePermissions.put(role, new HashSet<>(permissions));
        log.info("역할 권한 설정: role={}, permissions={}", role, permissions);
    }
    
    
    public void setToolRequiredPermissions(String toolName, Set<String> permissions) {
        toolRequiredPermissions.put(toolName, new HashSet<>(permissions));
        log.info("도구 필요 권한 설정: tool={}, permissions={}", toolName, permissions);
    }
    
    
    
    
    private void initializeDefaultPermissions() {
        
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
    
    
    private Set<String> loadUserPermissions(String userId) {
        
        Set<String> permissions = new HashSet<>();
        
        
        if ("admin".equals(userId)) {
            permissions.addAll(rolePermissions.get("ADMIN"));
        } else {
            permissions.addAll(rolePermissions.get("OPERATOR"));
        }
        
        log.debug("사용자 권한 로드: user={}, permissions={}", userId, permissions);
        return permissions;
    }
    
    
    private Set<String> determineToolPermissions(String toolName) {
        Set<String> permissions = new HashSet<>();
        
        
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
        
        
        permissions.add("tool.execute.basic");
        
        return permissions;
    }
    
    
    private boolean checkAdditionalPolicies(ToolCallback tool, ToolExecutor.ExecutionContext context) {
        
        if (context.isProductionEnvironment()) {
            String toolName = tool.getToolDefinition().name();
            if (toolName.contains("delete") || toolName.contains("kill") || 
                toolName.contains("shutdown")) {
                log.warn("운영 환경에서 위험한 도구 차단: {}", toolName);
                return false;
            }
        }
        
        
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
    
    
    private boolean processApproval(ToolExecutor.ApprovalRequest request) {
        
        
        
        String toolName = request.getToolName();
        String userId = request.getContext().getUserId();
        
        
        if (getUserPermissions(userId).contains("tool.approve.all")) {
            return true;
        }
        
        
        if (toolName.contains("read") || toolName.contains("view") || 
            toolName.contains("list")) {
            return true;
        }
        
        
        return false;
    }
    
    
    private String generateApprovalId(ToolExecutor.ApprovalRequest request) {
        return String.format("%s-%s-%d", 
            request.getToolName(),
            request.getContext().getUserId(),
            System.currentTimeMillis());
    }
    
    
    public Map<String, Object> getStatistics() {
        return Map.of(
            "userCount", userPermissions.size(),
            "roleCount", rolePermissions.size(),
            "toolCount", toolRequiredPermissions.size(),
            "pendingApprovals", pendingApprovals.size()
        );
    }
    
    
    public boolean hasAdminPrivileges(String userId) {
        if (userId == null) {
            return false;
        }
        
        
        Set<String> userPerms = getUserPermissions(userId);
        
        
        return "admin".equalsIgnoreCase(userId) || 
               userPerms.contains("security.admin") || 
               userPerms.containsAll(rolePermissions.getOrDefault("ADMIN", Collections.emptySet()));
    }
}