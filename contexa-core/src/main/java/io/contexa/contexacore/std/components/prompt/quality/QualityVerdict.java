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
 * What the comparison of two versions says of one rate (plan 3.3).
 */
public enum QualityVerdict {

    BETTER,

    /** No difference, or one no larger than two measurements of the same version differ. */
    SAME,

    WORSE,

    /** The cases cannot tell: there is nothing to pair, too few roots differ, or the noise is not measured yet. */
    UNDECIDABLE
}
