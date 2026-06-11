/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacommon.hcad.domain;

import lombok.Builder;
import lombok.Getter;


@Getter
@Builder
public class HCADAnalysisResult {

    
    private final String userId;

    
    private final double trustScore;

    
    private final String threatType;

    
    private final String threatEvidence;

    
    private final boolean isAnomaly;

    
    private final double anomalyScore;

    
    private final String action;

    
    private final double confidence;

    
    
    

    
    private final long processingTimeMs;

    
    private final HCADContext context;

    
    private final BaselineVector baseline;

    
    @Override
    public String toString() {
        return String.format(
            "HCADAnalysisResult{userId='%s', trust=%.3f, anomaly=%s, riskScore=%.3f, time=%dms}",
            userId, trustScore, isAnomaly, anomalyScore, processingTimeMs
        );
    }
}
