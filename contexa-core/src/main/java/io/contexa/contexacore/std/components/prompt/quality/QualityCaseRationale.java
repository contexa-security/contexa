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
package io.contexa.contexacore.std.components.prompt.quality;

/**
 * Why the expected answer of a case is the right one (plan 3.2), in Korean, in English, or both. The default set
 * carries both (plan 3.9).
 *
 * @param korean  the reason in Korean, or null
 * @param english the reason in English, or null
 */
public record QualityCaseRationale(String korean, String english) {

    public QualityCaseRationale {
        korean = korean == null || korean.isBlank() ? null : korean.trim();
        english = english == null || english.isBlank() ? null : english.trim();
        if (korean == null && english == null) {
            throw new IllegalArgumentException("A labelled case needs the reason of its answer");
        }
    }
}
