package io.contexa.demo.workspace.lease.dto;

public record WorkspaceUsage(
        int comparisonsUsed, int comparisonLimit,
        int chatUsed, int chatLimit,
        int embeddingUsed, int embeddingLimit,
        int workUsed, int workLimit
) {

}
