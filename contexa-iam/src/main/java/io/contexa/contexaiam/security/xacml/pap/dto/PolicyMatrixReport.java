package io.contexa.contexaiam.security.xacml.pap.dto;

import java.util.List;

public record PolicyMatrixReport(
        List<ResourceEntry> resources,
        List<String> roles,
        List<List<MatrixCell>> cells,
        List<ConflictCell> conflictCells) {

    public record ResourceEntry(
            String identifier,
            String httpMethod,
            String friendlyName) {
    }

    public record MatrixCell(
            String access,
            Long policyId,
            String policyName,
            boolean inherited) {
    }

    public record ConflictCell(
            int row,
            int col,
            String severity) {
    }
}
