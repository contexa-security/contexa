package io.contexa.contexaiam.aiam.protocol.response;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.contexa.contexacommon.domain.request.AIResponse;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

import java.util.ArrayList;
import java.util.List;


@Getter
@Setter
@ToString
public class AccessGovernanceResponse extends AIResponse {
    
    
    @JsonProperty("analysisId")
    private String analysisId;
    
    @JsonProperty("auditScope")
    private String auditScope;
    
    @JsonProperty("analysisType")
    private String analysisType;
    
    @JsonProperty("overallGovernanceScore")
    private double overallGovernanceScore;
    
    @JsonProperty("riskLevel")
    private String riskLevel;
    
    @JsonProperty("summary")
    private String summary;
    
    @JsonProperty("findings")
    private List<Finding> findings = new ArrayList<>();
    
    @JsonProperty("recommendations")
    private List<Recommendation> recommendations = new ArrayList<>();
    
    @JsonProperty("actionItems")
    private List<ActionItem> actionItems = new ArrayList<>();
    
    @JsonProperty("visualizationData")
    private VisualizationData visualizationData;
    
    @JsonProperty("statistics")
    private Statistics statistics;
    
    
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Finding {
        @JsonProperty("type")
        private String type;
        
        @JsonProperty("severity")
        private String severity;
        
        @JsonProperty("description")
        private String description;
        
        @JsonProperty("affectedUsers")
        private List<String> affectedUsers = new ArrayList<>();
        
        @JsonProperty("affectedRoles")
        private List<String> affectedRoles = new ArrayList<>();
        
        @JsonProperty("recommendation")
        private String recommendation;
    }
    
    
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Recommendation {
        @JsonProperty("category")
        private String category;
        
        @JsonProperty("priority")
        private String priority;
        
        @JsonProperty("title")
        private String title;
        
        @JsonProperty("description")
        private String description;
        
        @JsonProperty("implementationSteps")
        private List<String> implementationSteps = new ArrayList<>();
    }
    
    
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ActionItem {
        @JsonProperty("id")
        private String id;
        
        @JsonProperty("title")
        private String title;
        
        @JsonProperty("assignee")
        private String assignee;
        
        @JsonProperty("dueDate")
        private String dueDate;
        
        @JsonProperty("status")
        private String status;
        
        @JsonProperty("description")
        private String description;
    }
    
    
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class VisualizationData {
        @JsonProperty("nodes")
        private List<Node> nodes = new ArrayList<>();
        
        @JsonProperty("edges")
        private List<Edge> edges = new ArrayList<>();
        
        @Data
        @NoArgsConstructor
        @AllArgsConstructor
        public static class Node {
            @JsonProperty("id")
            private String id;
            
            @JsonProperty("type")
            private String type;
            
            @JsonProperty("label")
            private String label;
            
            @JsonProperty("permissions")
            private int permissions;
            
            @JsonProperty("riskLevel")
            private String riskLevel;
        }
        
        @Data
        @NoArgsConstructor
        @AllArgsConstructor
        public static class Edge {
            @JsonProperty("source")
            private String source;
            
            @JsonProperty("target")
            private String target;
            
            @JsonProperty("type")
            private String type;
        }
    }
    
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Statistics {
        @JsonProperty("totalUsers")
        private int totalUsers;
        
        @JsonProperty("totalRoles")
        private int totalRoles;
        
        @JsonProperty("totalGroups")
        private int totalGroups;
        
        @JsonProperty("totalPermissions")
        private int totalPermissions;
        
        @JsonProperty("dormantPermissions")
        private int dormantPermissions;
        
        @JsonProperty("excessivePermissions")
        private int excessivePermissions;
        
        @JsonProperty("sodViolations")
        private int sodViolations;
        
        @JsonProperty("emptyRoles")
        private int emptyRoles;
        
        @JsonProperty("emptyGroups")
        private int emptyGroups;
    }
    
    
    public AccessGovernanceResponse(String requestId) {
        super(requestId, ExecutionStatus.SUCCESS);
        this.findings = new ArrayList<>();
        this.recommendations = new ArrayList<>();
        this.actionItems = new ArrayList<>();
    }
    
    public AccessGovernanceResponse(String requestId, ExecutionStatus status) {
        super(requestId, status);
        this.findings = new ArrayList<>();
        this.recommendations = new ArrayList<>();
        this.actionItems = new ArrayList<>();
    }
    
    @Override
    public Object getData() {
        return this;
    }
    
    @Override
    public String getResponseType() {
        return "ACCESS_GOVERNANCE";
    }
} 