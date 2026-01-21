package io.contexa.contexacoreenterprise.mcp.integration;

import org.springframework.ai.tool.ToolCallback;
import io.contexa.contexacommon.annotation.SoarTool;

import java.util.Set;
import java.util.Optional;

public interface ToolIntegrationProvider {

    ToolCallback[] getToolCallbacks();

    Optional<ToolCallback> getToolCallback(String name);

    SoarTool.RiskLevel getToolRiskLevel(String name);

    boolean requiresApproval(String name);

    Set<String> getRegisteredToolNames();

    String getProviderType();

    boolean isReady();
}