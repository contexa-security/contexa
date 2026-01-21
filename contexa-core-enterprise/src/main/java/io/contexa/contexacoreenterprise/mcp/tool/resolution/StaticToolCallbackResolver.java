package io.contexa.contexacoreenterprise.mcp.tool.resolution;

import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.resolution.ToolCallbackResolver;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
public class StaticToolCallbackResolver implements ToolCallbackResolver {
    
    private final Map<String, ToolCallback> staticTools;
    
    public StaticToolCallbackResolver() {
        this(new ConcurrentHashMap<>());
    }
    
    public StaticToolCallbackResolver(Map<String, ToolCallback> initialTools) {
        this.staticTools = new ConcurrentHashMap<>(initialTools);
            }
    
    @Override
    public ToolCallback resolve(String toolName) {

        ToolCallback tool = staticTools.get(toolName);
        if (tool != null) {
                    }
        
        return tool;
    }

    public void registerTool(ToolCallback tool) {
        String toolName = tool.getToolDefinition().name();
        staticTools.put(toolName, tool);
            }

    public void registerTools(ToolCallback... tools) {
        for (ToolCallback tool : tools) {
            registerTool(tool);
        }
    }

    public void unregisterTool(String toolName) {
        ToolCallback removed = staticTools.remove(toolName);
        if (removed != null) {
                    }
    }

    public void clear() {
        int count = staticTools.size();
        staticTools.clear();
            }

    public boolean hasTool(String toolName) {
        return staticTools.containsKey(toolName);
    }

    public int getToolCount() {
        return staticTools.size();
    }

    public String[] getToolNames() {
        return staticTools.keySet().toArray(String[]::new);
    }

    public Map<String, ToolCallback> getAllTools() {
        return new ConcurrentHashMap<>(staticTools);
    }

    public Map<String, Object> getStatistics() {
        return Map.of(
            "totalTools", staticTools.size(),
            "toolNames", staticTools.keySet()
        );
    }
}