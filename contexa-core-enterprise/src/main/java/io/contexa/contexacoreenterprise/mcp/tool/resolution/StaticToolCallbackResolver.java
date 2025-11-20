package io.contexa.contexacoreenterprise.mcp.tool.resolution;

import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.resolution.ToolCallbackResolver;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * StaticToolCallbackResolver
 * 
 * 정적으로 등록된 도구들을 관리하고 해결합니다.
 * 런타임에 동적으로 도구를 추가/제거할 수 있습니다.
 */
@Slf4j
@Component
public class StaticToolCallbackResolver implements ToolCallbackResolver {
    
    private final Map<String, ToolCallback> staticTools;
    
    public StaticToolCallbackResolver() {
        this(new ConcurrentHashMap<>());
    }
    
    public StaticToolCallbackResolver(Map<String, ToolCallback> initialTools) {
        this.staticTools = new ConcurrentHashMap<>(initialTools);
        log.info("StaticToolCallbackResolver 초기화: {} 개의 도구", staticTools.size());
    }
    
    @Override
    public ToolCallback resolve(String toolName) {

        log.trace("정적 도구 검색: {}", toolName);
        
        ToolCallback tool = staticTools.get(toolName);
        if (tool != null) {
            log.debug("정적 도구 발견: {}", toolName);
        }
        
        return tool;
    }
    
    /**
     * 도구 등록
     */
    public void registerTool(ToolCallback tool) {
        String toolName = tool.getToolDefinition().name();
        staticTools.put(toolName, tool);
        log.info("정적 도구 등록: {}", toolName);
    }
    
    /**
     * 여러 도구 등록
     */
    public void registerTools(ToolCallback... tools) {
        for (ToolCallback tool : tools) {
            registerTool(tool);
        }
    }
    
    /**
     * 도구 제거
     */
    public void unregisterTool(String toolName) {
        ToolCallback removed = staticTools.remove(toolName);
        if (removed != null) {
            log.info("정적 도구 제거: {}", toolName);
        }
    }
    
    /**
     * 모든 도구 제거
     */
    public void clear() {
        int count = staticTools.size();
        staticTools.clear();
        log.info("모든 정적 도구 제거: {} 개", count);
    }
    
    /**
     * 도구 존재 여부 확인
     */
    public boolean hasTool(String toolName) {
        return staticTools.containsKey(toolName);
    }
    
    /**
     * 등록된 도구 개수
     */
    public int getToolCount() {
        return staticTools.size();
    }
    
    /**
     * 모든 도구 이름 반환
     */
    public String[] getToolNames() {
        return staticTools.keySet().toArray(String[]::new);
    }
    
    /**
     * 모든 도구 반환
     */
    public Map<String, ToolCallback> getAllTools() {
        return new ConcurrentHashMap<>(staticTools);
    }
    
    /**
     * 통계 정보
     */
    public Map<String, Object> getStatistics() {
        return Map.of(
            "totalTools", staticTools.size(),
            "toolNames", staticTools.keySet()
        );
    }
}