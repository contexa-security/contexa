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
package io.contexa.contexacore.hcad.projection;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public record HcadPromptSecurityContextFieldContract(
        String hcadField,
        String promptLabel,
        String officialMetadataKey,
        String canonicalPath,
        List<HcadTrustedSource> allowedSources,
        HcadPromptSecurityContextFieldUse use,
        String normalizer,
        String owner,
        boolean scoringAllowed,
        String exclusionReason
) {

    public HcadPromptSecurityContextFieldContract {
        allowedSources = allowedSources == null ? List.of() : List.copyOf(allowedSources);
        use = use == null ? HcadPromptSecurityContextFieldUse.EXCLUDED : use;
        normalizer = normalizer == null ? "" : normalizer;
        owner = owner == null ? "" : owner;
        exclusionReason = exclusionReason == null ? "" : exclusionReason;
    }

    public boolean allowsScoringFrom(HcadTrustedSource source) {
        return scoringAllowed
                && source != null
                && allowedSources.contains(source);
    }

    public Map<String, Object> toSnapshot() {
        Map<String, Object> snapshot = new LinkedHashMap<>();
        snapshot.put("hcadField", hcadField);
        snapshot.put("promptLabel", promptLabel);
        snapshot.put("officialMetadataKey", officialMetadataKey);
        snapshot.put("canonicalPath", canonicalPath);
        snapshot.put("allowedSources", allowedSources.stream().map(Enum::name).toList());
        snapshot.put("use", use.name());
        snapshot.put("normalizer", normalizer);
        snapshot.put("owner", owner);
        snapshot.put("scoringAllowed", scoringAllowed);
        snapshot.put("exclusionReason", exclusionReason);
        return snapshot;
    }
}
