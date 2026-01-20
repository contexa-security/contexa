package io.contexa.contexacommon.mcp.tool;

import org.springframework.ai.tool.ToolCallback;


public interface ToolResolver {

    
    ToolCallback[] getAllToolCallbacks();
}
