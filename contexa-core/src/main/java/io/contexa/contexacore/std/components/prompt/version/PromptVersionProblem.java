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
package io.contexa.contexacore.std.components.prompt.version;

import java.util.Objects;

/**
 * Why a prompt version document cannot be saved (plan 3.5 and 3.6): what is wrong, where, and the detail a screen
 * names in its own words. A document with any problem is not saved.
 *
 * @param code   what is wrong
 * @param where  the part, block or field it is wrong at ({@code system.how-to-judge}, {@code kind}); may be null
 * @param detail the value or the numbers behind it; may be null
 */
public record PromptVersionProblem(Code code, String where, String detail) {

    public PromptVersionProblem {
        Objects.requireNonNull(code, "code");
    }

    /** What can be wrong with a document. */
    public enum Code {
        /** The text is not a YAML mapping of the document form. */
        FORMAT,
        /** A field the document form does not have, or one an organization's part cannot set. */
        UNKNOWN_FIELD,
        /** A field the document needs is missing. */
        MISSING_FIELD,
        /** A field holds a value of the wrong kind or out of its choices. */
        BAD_VALUE,
        /** The document is for another prompt than its base. */
        OTHER_PROMPT,
        /** The document is a rendered copy, for reading only. */
        RENDERED_DOCUMENT,
        /** An organization's document names no base version, or one this server does not have. */
        NO_BASE,
        /**
         * The screen makes a version on a base that came from a document (an import or the document folder): the
         * document is where that version is changed (plan 3.3).
         */
        BASE_FROM_DOCUMENT,
        /** The document is one version of the same origin already registered. */
        ALREADY_REGISTERED,
        /** A version that a decision uses, a canary or a shadow runs, cannot be hidden. */
        IN_USE,
        /** A part Contexa fixed is changed or deleted. */
        LOCKED_PART,
        /** A part or block the base does not have is changed, deleted or included. */
        UNKNOWN_PART,
        /** An added part is placed after a part the base does not have, or where no part may go. */
        UNKNOWN_PLACE,
        /** A part a version includes is not one Contexa prepared. */
        NOT_PREPARED,
        /** An added part has no title. */
        EMPTY_TITLE,
        /** An added or changed part has no text. */
        EMPTY_TEXT,
        /** Two parts have the same key, or an added part has the key of a part of the base. */
        DUPLICATE_KEY,
        /**
         * K67: a block added to the user prompt is titled as a block of the engine, so its header would read as that
         * block's; the security decision draws such a title of a version saved earlier in quotes.
         */
        ENGINE_TITLE,
        /** The finished prompt with the longest recent input and the answer does not fit the model's context. */
        TOO_LONG
    }
}
