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
 * How the quality gate acts on its verdict (plan 3.4, 5 step 5): it goes in as a warning first and blocks once the
 * reproducibility and the discrimination checks of plan 6 have passed. An installation can lower the whole gate to a
 * warning.
 */
public enum QualityGateMode {

    /** A blocked verdict is applied as a warning; the verdict itself is kept as it was. The default. */
    WARN,

    /** A blocked verdict blocks; an operator may override it with a reason. */
    BLOCK
}
