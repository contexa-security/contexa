package io.contexa.contexacore.mcp.integration;

import org.springframework.ai.tool.ToolCallback;
import io.contexa.contexacommon.annotation.SoarTool;

import java.util.Set;
import java.util.Optional;

/**
 * Tool Integration Provider Interface
 * 
 * 도구 통합을 위한 표준 인터페이스입니다.
 * MCP와 SOAR 프로바이더가 이 인터페이스를 구현하여
 * 순환 의존성 없이 통합될 수 있습니다.
 */
public interface ToolIntegrationProvider {
    
    /**
     * 모든 Tool Callback 반환
     * 
     * @return Tool Callback 배열
     */
    ToolCallback[] getToolCallbacks();
    
    /**
     * 특정 도구 가져오기
     * 
     * @param name 도구 이름
     * @return Optional로 래핑된 ToolCallback
     */
    Optional<ToolCallback> getToolCallback(String name);
    
    /**
     * 도구의 위험도 레벨 확인
     * 
     * @param name 도구 이름
     * @return 위험도 레벨
     */
    SoarTool.RiskLevel getToolRiskLevel(String name);
    
    /**
     * 승인이 필요한 도구인지 확인
     * 
     * @param name 도구 이름
     * @return 승인 필요 여부
     */
    boolean requiresApproval(String name);
    
    /**
     * 등록된 도구 이름 목록
     * 
     * @return 도구 이름 Set
     */
    Set<String> getRegisteredToolNames();
    
    /**
     * 프로바이더 타입
     * 
     * @return 프로바이더 타입 문자열
     */
    String getProviderType();
    
    /**
     * 프로바이더 준비 상태
     * 
     * @return 준비 완료 여부
     */
    boolean isReady();
}