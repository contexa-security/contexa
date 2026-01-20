package io.contexa.contexacoreenterprise.soar.tool.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;


@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SoarToolCall {
    
    
    private String id;
    
    
    private String name;
    
    
    private String arguments;
    
    
    @Builder.Default
    private String type = "function";
    
    
    private String description;
    
    
    @Builder.Default
    private String riskLevel = "MEDIUM";
    
    
    @Builder.Default
    private boolean approvalRequired = false;
    
    
    @Builder.Default
    private ToolCallStatus status = ToolCallStatus.PENDING;
    
    
    private String result;
    
    
    private String error;
    
    
    public enum ToolCallStatus {
        PENDING,       
        APPROVED,      
        REJECTED,      
        EXECUTING,     
        COMPLETED,     
        FAILED         
    }
    
    
    public boolean isSuccess() {
        return status == ToolCallStatus.COMPLETED && error == null;
    }
    
    
    public boolean isExecutable() {
        return status == ToolCallStatus.APPROVED || 
               (status == ToolCallStatus.PENDING && !approvalRequired);
    }
}