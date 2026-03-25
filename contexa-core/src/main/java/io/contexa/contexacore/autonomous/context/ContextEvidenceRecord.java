package io.contexa.contexacore.autonomous.context;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ContextEvidenceRecord {

    private String evidenceId;

    private String observedAt;

    private String summary;

    private String decisionState;

    private Boolean protectable;

    @Builder.Default
    private Map<String, String> sourceKeys = new LinkedHashMap<>();

    @Builder.Default
    private List<String> flags = new ArrayList<>();
}
