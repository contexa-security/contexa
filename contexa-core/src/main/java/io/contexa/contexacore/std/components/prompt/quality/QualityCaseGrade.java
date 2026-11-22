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
 * The grade of a labelled case (plan 3.2). The quality gate allows no single failure on the two graded ones: a case
 * that must be caught is never allowed, a case that must not be blocked is never blocked.
 */
public enum QualityCaseGrade {

    ORDINARY,

    /** Must be caught, such as an account takeover the server itself confirmed. */
    MUST_CATCH,

    /** Must not be blocked. */
    MUST_NOT_BLOCK
}
