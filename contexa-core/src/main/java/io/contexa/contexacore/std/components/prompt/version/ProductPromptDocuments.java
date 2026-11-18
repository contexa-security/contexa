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

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * The product documents of a prompt as the build ships them (plan 3.3, 3.11): {@code prompt-versions/{prompt}/{release}
 * .yaml} beside the class that draws the prompt, the latest release last. The product version is the latest release's
 * document as it is; a version a store keeps stands on it.
 */
public final class ProductPromptDocuments {

    private final String prompt;
    private final List<ProductPromptRelease> releases;
    private final AssembledPrompt product;
    /** The product version of every release, by the release name its document gives, oldest first. */
    private final Map<String, AssembledPrompt> byRelease;

    /**
     * @param anchor   a class of the module that ships the documents, whose class loader reads them
     * @param prompt   the prompt key, such as {@code ResourceNaming}
     * @param releases the releases the build ships, oldest first
     */
    public ProductPromptDocuments(Class<?> anchor, String prompt, List<String> releases) {
        Objects.requireNonNull(anchor, "anchor");
        this.prompt = Objects.requireNonNull(prompt, "prompt");
        if (releases == null || releases.isEmpty()) {
            throw new IllegalArgumentException("The prompt " + prompt + " ships no product document");
        }
        List<ProductPromptRelease> read = new ArrayList<>();
        Map<String, AssembledPrompt> versions = new LinkedHashMap<>();
        AssembledPrompt latest = null;
        for (String release : releases) {
            String text = resource(anchor, prompt, release);
            PromptVersionDocument document = new PromptVersionDocumentReader().read(text);
            if (!prompt.equals(document.prompt())) {
                throw new IllegalStateException("The product document " + release + " of " + prompt + " is for "
                        + document.prompt());
            }
            read.add(new ProductPromptRelease(prompt, document.release(), text));
            latest = new PromptAssembler().product(document);
            versions.put(latest.release(), latest);
        }
        this.releases = List.copyOf(read);
        this.product = latest;
        this.byRelease = Collections.unmodifiableMap(versions);
    }

    /** The prompt key. */
    public String prompt() {
        return prompt;
    }

    /** The product documents, oldest first, as the version service registers them. */
    public List<ProductPromptRelease> releases() {
        return releases;
    }

    /** The product version: the latest release's document. */
    public AssembledPrompt product() {
        return product;
    }

    /**
     * The store of the product versions, each named by its release (N3): an earlier release the build ships is found
     * by its own name as the latest is, not only through the version tables.
     */
    public PromptVersionStore store() {
        return (asked, version) -> prompt.equals(asked) && version != null
                ? Optional.ofNullable(byRelease.get(version.trim())) : Optional.empty();
    }

    /** The text of the product document of a release, as the build ships it. */
    public static String resource(Class<?> anchor, String prompt, String release) {
        String path = "prompt-versions/" + prompt + "/" + release + ".yaml";
        try (InputStream input = anchor.getClassLoader().getResourceAsStream(path)) {
            if (input == null) {
                throw new IllegalStateException("The product prompt document is missing: " + path);
            }
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
        catch (IOException exception) {
            throw new UncheckedIOException(exception);
        }
    }
}
