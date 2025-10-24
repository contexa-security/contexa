package io.contexa.contexaiam.admin.support.visualization.dto;

import java.util.List;
import java.util.Map;

public record GraphDataDto(List<Node> nodes, List<Edge> edges) {
    public record Node(String id, String label, String type, Map<String, Object> properties) {}
    public record Edge(String from, String to, String label) {}
}