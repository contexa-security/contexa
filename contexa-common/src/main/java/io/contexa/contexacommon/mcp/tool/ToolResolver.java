package io.contexa.contexacommon.mcp.tool;

import org.springframework.ai.tool.ToolCallback;

/**
 * Chained Tool Resolver Interface
 *
 * <p>
 * Core와 Enterprise 사이의 MCP Tool Resolution 인터페이스입니다.
 * Enterprise가 있으면 실제 Tool Resolver가 동작하고, 없으면 빈 배열 반환.
 * </p>
 *
 * @since 0.1.1
 */
public interface ToolResolver {

    /**
     * 모든 Tool Callback 조회
     *
     * @return Tool Callback 배열
     */
    ToolCallback[] getAllToolCallbacks();
}
