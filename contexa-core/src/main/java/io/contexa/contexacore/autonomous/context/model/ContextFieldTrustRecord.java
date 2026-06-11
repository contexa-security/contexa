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
package io.contexa.contexacore.autonomous.context.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;
import io.contexa.contexacore.autonomous.context.model.ContextQualityGrade;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
/**
 * Field-level evidence lineage and coverage metadata. This record packages provenance and evidence
 * sufficiency only; it is not a semantic legitimacy, abuse, or intent verdict.
 */
public class ContextFieldTrustRecord {

    private String fieldPath;

    private String semanticMeaning;

    private String intendedUse;

    private String provenanceSummary;

    private Integer observationCount;

    private Integer daysCovered;

    private Double fallbackRate;

    private Double unknownRate;

    /**
     * Audit-only evidence sufficiency grade. Never expose this as a semantic conclusion.
     */
    private ContextQualityGrade qualityGrade;

    /**
     * Audit-only evidence sufficiency score. Never expose this as a semantic conclusion.
     */
    private Integer qualityScore;

    private String qualitySummary;

    @Builder.Default
    private List<String> sourceKeys = new ArrayList<>();

    @Builder.Default
    private List<String> fallbackSourceKeys = new ArrayList<>();

    @Builder.Default
    private List<String> evidenceIds = new ArrayList<>();
}
