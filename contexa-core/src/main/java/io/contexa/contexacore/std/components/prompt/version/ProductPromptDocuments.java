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
import java.util.List;
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
        PromptVersionDocument latest = null;
        for (String release : releases) {
            String text = resource(anchor, prompt, release);
            latest = new PromptVersionDocumentReader().read(text);
            if (!prompt.equals(latest.prompt())) {
                throw new IllegalStateException("The product document " + release + " of " + prompt + " is for "
                        + latest.prompt());
            }
            read.add(new ProductPromptRelease(prompt, latest.release(), text));
        }
        this.releases = List.copyOf(read);
        this.product = new PromptAssembler().product(latest);
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

    /** The store of the product version, named by its release. */
    public PromptVersionStore store() {
        return (asked, version) -> prompt.equals(asked) && product.release().equals(version)
                ? Optional.of(product) : Optional.empty();
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
