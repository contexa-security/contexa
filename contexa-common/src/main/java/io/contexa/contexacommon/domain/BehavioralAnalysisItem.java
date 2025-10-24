package io.contexa.contexacommon.domain;

import lombok.Data;

@Data
public class BehavioralAnalysisItem {

    private String userId;
    private String query;
    private boolean stream;
}
