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
package io.contexa.contexaiam.admin.promptquality.version;

import io.contexa.contexacore.std.components.prompt.version.PromptVersionNames;

import java.time.Instant;

/**
 * One row of {@code ctxa_prompt_version} (plan 3.7): a version as it was registered.
 *
 * @param provider          who made it: CONTEXA (a product document) or ORGANIZATION
 * @param origin            where it came from: PRODUCT, SCREEN, IMPORT or FOLDER
 * @param originName        the release, the document's file name, or the screen's own name for the save
 * @param originContentHash the hash of the document's text as it came
 * @param contentHash       the content hash of the assembled version (plan 3.7): the same prompt, the same hash
 * @param document          the document the version was made from, as it was read
 */
public record PromptVersionRecord(
        long id,
        String scope,
        String prompt,
        int number,
        String title,
        String description,
        Integer basedOnNumber,
        String basedOnHash,
        String provider,
        String origin,
        String originName,
        String originContentHash,
        String contentHash,
        String document,
        boolean hidden,
        String createdBy,
        Instant createdAt) {

    public static final String CONTEXA = "CONTEXA";
    public static final String ORGANIZATION = "ORGANIZATION";
    public static final String PRODUCT = "PRODUCT";
    public static final String SCREEN = "SCREEN";
    public static final String IMPORT = "IMPORT";
    public static final String FOLDER = "FOLDER";

    /** The name a screen shows and an event names: {@code v2.0}. */
    public String name() {
        return PromptVersionNames.name(number);
    }

    /** Whether the version came from a document a person changes outside the screen (an import or the folder). */
    public boolean fromDocument() {
        return IMPORT.equals(origin) || FOLDER.equals(origin);
    }
}
