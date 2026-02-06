package io.contexa.contexaiam.aiam.protocol.response;

import io.contexa.contexacommon.domain.request.AIResponse;
import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Getter
@Setter
public class StudioQueryResponse extends AIResponse {

    private String analysisId;

    private String query;

    private double confidenceScore;

    private String naturalLanguageAnswer;

    private List<QueryResult> queryResults = new ArrayList<>();

    private List<AnalysisResult> analysisResults = new ArrayList<>();

    private VisualizationData visualizationData;

    private List<Recommendation> recommendations = new ArrayList<>();

    private long processingTimeMs;

    public StudioQueryResponse(String requestId) {
        super(requestId, ExecutionStatus.SUCCESS);
    }

    @Getter
    @Setter
    public static class QueryResult {
        private String entity;           
        private String actionType;       
        private String description;      
        private int relevanceScore;      
        private Map<String, Object> metadata = new HashMap<>();
    }

    @Getter
    @Setter
    public static class AnalysisResult {
        private String user;         
        private List<String> groups;        
        private List<String> roles;         
        private List<String> permissions;   
        private boolean hasPermission;   
        private String description;      
        private Map<String, Object> metadata = new HashMap<>();
    }

    @Getter
    @Setter
    public static class VisualizationData {
        private String graphType;         
        private String title;            
        private String description;      
        private List<Node> nodes = new ArrayList<>();
        private List<Edge> edges = new ArrayList<>();
        private Map<String, Object> layoutConfig = new HashMap<>();
        private Map<String, String> styling = new HashMap<>();
        
        @Getter
        @Setter
        public static class Node {
            private String id;
            private String label;
            private String type;
            private String category;
            private String color;        
            private boolean highlighted = false;
            private Map<String, Object> properties = new HashMap<>();
            private Map<String, Object> metadata = new HashMap<>();
        }
        
        @Getter
        @Setter
        public static class Edge {
            private String id;
            private String source;
            private String target;
            private String relationship;
            private String label;
            private String type;         
            private String color;        
            private boolean highlighted = false;
            private boolean dashed = false; 
            private Map<String, Object> properties = new HashMap<>();
        }
    }

    @Getter
    @Setter
    public static class Recommendation {
        private String title;            
        private String description;      
        private int priority = 2;        
        private String category;        
        private String type;            
        private List<String> actionItems = new ArrayList<>(); 
        private List<ActionLink> actionLinks = new ArrayList<>(); 
        private Map<String, Object> metadata = new HashMap<>();
        
        public void setType(String type) {
            this.type = type;
            this.category = type; 
        }
    }

    @Getter
    @Setter
    public static class ActionLink {
        private String text;            
        private String url;             
        private String type;            
        private String icon;            
        private boolean openInNewTab = false;  
        private Map<String, Object> metadata = new HashMap<>();
    }
}