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
package io.contexa.contexacore.autonomous.saas.learning.portfolio;
import java.util.List;
/**
 * Optimization recommendation for the learning artifact portfolio.
 */
public record CrossArtifactPortfolioRecommendation(
        String code,
        String summary,
        boolean blocking,
        List<String> artifactTypes,
        String recommendedAction) {
    public CrossArtifactPortfolioRecommendation {
        artifactTypes = artifactTypes == null ? List.of() : List.copyOf(artifactTypes);
    }
}
