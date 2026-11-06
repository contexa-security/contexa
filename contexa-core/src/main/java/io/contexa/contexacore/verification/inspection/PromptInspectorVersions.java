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
                    + "ledger nobody writes is no reason for a different prompt (R1b-9)"),
            new Version(17, "the reason codes of the decision checked against the facts they cite (W4-8 REASON_MATCH), "
                    + "and the UNKNOWN line's names read after the IDs it gives them (N-UID-1)"),
            new Version(18, "the facts compared with the host's own records of them (W6-7 SOURCE_TRUTH), the past "
                    + "records the prompt drew named by their stored IDs (W6-12) and every model call of the decision "
                    + "kept with the applied stage's prompt, the sealed prompt compared with the one the last model "
                    + "call sent (W6-6)"),
            new Version(19, "a source fact the UNKNOWN line names counted as its missing notation, not as a line the "
                    + "prompt left out (N-SRC-1)"),
            new Version(20, "the target's business label compared on the UNTRUSTED TEXT line that holds its text, the "
                    + "target line saying only where it is (N-INJ-3); an entry without a value graded by its own "
                    + "missing notation: an UNKNOWN name in place of a missing text, unless the sealed context lacks "
                    + "its source by the render's rule, and one of an entry left out with its line or block, unless "
                    + "the seal shows the render's caller named it, pointed at (N-INS-2); a name after a word the "
                    + "render does not write in a kind's place read under that word (N-INS-3); a host that does not "
                    + "keep the records of the sealed decision counted as its facts not compared, not as a source "
                    + "without facts (N-SRC-2)"),
            new Version(21, "the past records' reasons compared with the sealed search state: the state line without "
                    + "the event clock, and the UNKNOWN line's past record names by kind and reason (N-INS-4)"),
            new Version(22, "a target category that is not a token compared on the UNTRUSTED TEXT line that holds its "
                    + "text, the target line saying only where it is (N-INJ-4); the decision's output retries compared "
                    + "with its model call stages and the last one with its single retry fields (N-OUT-3)"),
            new Version(23, "a v21 package read as a dictionary prompt with the v21 dictionary, its decision facts "
                    + "computed again in the records notation and its reason codes checked against the output "
                    + "contract v4 (V-6 of the v21 plan)"),
            new Version(24, "the scope the host's records hold the target in compared on its v21 line with the sealed "
                    + "resource (finding 7 of the v21 plan)"),
            new Version(25, "a v21 reason code of an earlier allowed record on the same target matched on the past "
                    + "records' counted fact as on a record line (finding 12 of the v21 plan)"),
            new Version(26, "a v21 argument origin line and the tool output sentences quoted as untrusted texts compared "
                    + "with the origins the sealed context holds, and the reason code of a value from a tool's output "
                    + "checked against them (CQ-1)"),
            new Version(27, "a v21 past record line with the learned field and, for a record with arguments from a tool's "
                    + "output, the arguments field, compared with the sealed records that keep how they were learned "
                    + "(BR-C6)"),
            new Version(28, "a package without the signature it should carry, whatever schema it names, and one whose "
                    + "predecessor is gone inside the retention, pointed at (Q-21)"),
            new Version(29, "a package that names a signing key the installation never held, and a lowered package with "
                    + "any text as its signature"));

    private PromptInspectorVersions() {
    }

    /** The version the inspector runs now. */
    public static Version current() {
        return ALL.isEmpty() ? new Version(0, "") : ALL.get(ALL.size() - 1);
    }
}
