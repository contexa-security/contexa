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
package io.contexa.contexacore.verification.inspection;

import java.util.List;

/**
 * Every raise of the prompt inspector's version with why, in one place (R1b-7): a stored result names the version it
 * was inspected with, and this list says what that version finds that the one before did not.
 */
public final class PromptInspectorVersions {

    /** One version: its number and what made the checks find something else. */
    public record Version(int number, String reason) {

        public String name() {
            return "prompt-inspector/" + number;
        }
    }

    public static final List<Version> ALL = List.of(
            new Version(1, "the inspector's first checks: seal integrity, dictionary contract, decision facts, fact "
                    + "accuracy, declared unknowns and past record notation (W3-15R R1)"),
            new Version(2, "the bundle trace against the prompt release registry (W3-15R R3)"),
            new Version(3, "the past records of the exact lookup (W3-18)"),
            new Version(4, "the evidence line's baseline state (W3-19)"),
            new Version(5, "the fact IDs of every cited block (P3 extra 12)"),
            new Version(6, "the coverage levels as parts of the line (W3-5)"),
            new Version(7, "the evidence line without the baseline state (W3-19 Q-79)"),
            new Version(8, "the status line compared with the sealed baseline state (R1b-1)"),
            new Version(9, "the render's own value functions: requests of the same time expected in the render's "
                    + "order (R1b-2)"),
            new Version(10, "one place of each rule the render and the checks share: an unknown kind is a word the "
                    + "renderer draws and its reason is compared as the renderer trims it (R1b-3); the differences "
                    + "line without a difference may state the closest past record (P3 extra 39)"),
            new Version(11, "the usual lines of a user without any learning compared with the sealed NONE state "
                    + "(R1b-4, P3 extra 41)"),
            new Version(12, "one rule for sealed sources that do not read: named once and the lines drawn from them "
                    + "left unchecked (R1b-5)"),
            new Version(13, "a package sealed under another bundle's prompt dictionary is not read against this one, "
                    + "and a result names its dictionary by the digest of its content (R1b-7, P3 extra 17)"),
            new Version(14, "the REQUEST lines and the coverage line compared whole through the render's value "
                    + "functions, and a package read only when its bundle has this build's dictionary and render "
                    + "(R1b-7, P3 extra 35)"),
            new Version(15, "the same-fact check: a fact two lines state has one value (R1b-8, plan C2)"),
            new Version(16, "the seal trace compares the request facts' request id with the package, and a layout "
                    + "ledger nobody writes is no reason for a different prompt (R1b-9)"));

    private PromptInspectorVersions() {
    }

    /** The version the inspector runs now. */
    public static Version current() {
        return ALL.isEmpty() ? new Version(0, "") : ALL.get(ALL.size() - 1);
    }
}
