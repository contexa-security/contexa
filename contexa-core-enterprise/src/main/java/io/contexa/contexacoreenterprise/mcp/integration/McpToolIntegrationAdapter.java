package io.contexa.contexacoreenterprise.mcp.integration;

import io.contexa.contexacommon.annotation.SoarTool;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

/**
 * MCP Tool Integration Adapter
 * 
 * McpFunctionCallbackProvider를 ToolIntegrationProvider 인터페이스로 어댑팅합니다.
 * 이를 통해 순환 의존성 없이 MCP 도구를 통합할 수 있습니다.
 */
@Slf4j
@Component("mcpToolIntegrationAdapter")
@ConditionalOnBean(McpFunctionCallbackProvider.class)
@RequiredArgsConstructor
public class McpToolIntegrationAdapter implements ToolIntegrationProvider {
    
    private final McpFunctionCallbackProvider mcpProvider;
    
    /**
     * MCP Tool Callback 반환
     */
    @Override
    public ToolCallback[] getToolCallbacks() {
        try {
            return mcpProvider.getMcpToolCallbacks();
        } catch (Exception e) {
            log.warn("MCP 도구 가져오기 실패: {}", e.getMessage());
            return new ToolCallback[0];
        }
    }
    
    /**
     * 특정 MCP 도구 가져오기
     */
    @Override
    public Optional<ToolCallback> getToolCallback(String name) {
        try {
            ToolCallback[] callbacks = getToolCallbacks();
            for (ToolCallback callback : callbacks) {
                if (callback.getToolDefinition().name().equals(name)) {
                    return Optional.of(callback);
                }
            }
        } catch (Exception e) {
            log.warn("MCP 도구 {} 조회 실패: {}", name, e.getMessage());
        }
        return Optional.empty();
    }
    
    /**
     * MCP 도구의 위험도 레벨
     * MCP 도구는 기본적으로 LOW 위험도로 처리
     */
    @Override
    public SoarTool.RiskLevel getToolRiskLevel(String name) {
        // MCP 도구는 주로 조회/검색 도구이므로 기본적으로 LOW
        // 필요시 도구 이름별로 세분화 가능
        if (name != null) {
            if (name.contains("delete") || name.contains("remove")) {
                return SoarTool.RiskLevel.MEDIUM;
            }
            if (name.contains("search") || name.contains("query")) {
                return SoarTool.RiskLevel.LOW;
            }
        }
        return SoarTool.RiskLevel.LOW;
    }
    
    /**
     * MCP 도구 승인 필요 여부
     * 기본적으로 MCP 도구는 승인 불필요
     */
    @Override
    public boolean requiresApproval(String name) {
        // MCP 도구는 대부분 읽기 전용이므로 승인 불필요
        // 특정 도구만 승인 필요하도록 설정 가능
        SoarTool.RiskLevel riskLevel = getToolRiskLevel(name);
        return riskLevel == SoarTool.RiskLevel.HIGH || 
               riskLevel == SoarTool.RiskLevel.CRITICAL;
    }
    
    /**
     * 등록된 MCP 도구 이름 목록
     */
    @Override
    public Set<String> getRegisteredToolNames() {
        Set<String> names = new HashSet<>();
        try {
            ToolCallback[] callbacks = getToolCallbacks();
            for (ToolCallback callback : callbacks) {
                names.add(callback.getToolDefinition().name());
            }
        } catch (Exception e) {
            log.warn("MCP 도구 이름 목록 조회 실패: {}", e.getMessage());
        }
        return names;
    }
    
    /**
     * 프로바이더 타입
     */
    @Override
    public String getProviderType() {
        return "MCP";
    }
    
    /**
     * 프로바이더 준비 상태
     */
    @Override
    public boolean isReady() {
        try {
            return mcpProvider != null && getToolCallbacks().length > 0;
        } catch (Exception e) {
            return false;
        }
    }
}