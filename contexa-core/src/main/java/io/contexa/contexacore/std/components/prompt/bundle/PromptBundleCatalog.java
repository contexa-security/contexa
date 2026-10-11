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
package io.contexa.contexacore.std.components.prompt.bundle;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The prompt bundle manifests shipped with the build ({@code prompt-bundles/manifests/<promptKey>/<version>.json} on the
 * classpath). Manifests are checked when they are read: a bundle hash that does not match its elements, or two
 * manifests with the same name, fail fast.
 */
public final class PromptBundleCatalog {

    public static final String MANIFEST_PATTERN = "classpath*:prompt-bundles/manifests/*/*.json";
    public static final String BUILD_DEFAULT_SELECTION = "BUILD_DEFAULT";

    private static volatile PromptBundleCatalog shared;

    private final Map<String, PromptBundleManifest> manifests;

    public PromptBundleCatalog(List<PromptBundleManifest> manifests) {
        Map<String, PromptBundleManifest> byName = new LinkedHashMap<>();
        for (PromptBundleManifest manifest : manifests) {
            PromptBundleManifest previous = byName.put(key(manifest.promptKey(), manifest.bundleVersion()), manifest);
            if (previous != null && !previous.bundleHash().equals(manifest.bundleHash())) {
                throw new IllegalStateException("Prompt bundle " + manifest.promptKey() + "@" + manifest.bundleVersion()
                        + " is declared with two different hashes");
            }
        }
        this.manifests = Map.copyOf(byName);
    }

    public static PromptBundleCatalog shared() {
        PromptBundleCatalog catalog = shared;
        if (catalog == null) {
            synchronized (PromptBundleCatalog.class) {
                catalog = shared;
                if (catalog == null) {
                    catalog = load(PromptBundleCatalog.class.getClassLoader());
                    shared = catalog;
                }
            }
        }
        return catalog;
    }

    public static PromptBundleCatalog load(ClassLoader classLoader) {
        ObjectMapper objectMapper = new ObjectMapper()
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        List<PromptBundleManifest> manifests = new ArrayList<>();
        try {
            Resource[] resources = new PathMatchingResourcePatternResolver(classLoader).getResources(MANIFEST_PATTERN);
            for (Resource resource : resources) {
                try (InputStream input = resource.getInputStream()) {
                    manifests.add(objectMapper.readValue(input, PromptBundleManifest.class));
                }
                catch (IOException | IllegalArgumentException exception) {
                    throw new IllegalStateException("Invalid prompt bundle manifest " + resource.getDescription(), exception);
                }
            }
        }
        catch (IOException exception) {
            throw new IllegalStateException("Prompt bundle manifests could not be listed", exception);
        }
        return new PromptBundleCatalog(manifests);
    }

    public Optional<PromptBundleManifest> find(String promptKey, String bundleVersion) {
        if (promptKey == null || bundleVersion == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(manifests.get(key(promptKey, bundleVersion)));
    }

    /**
     * The newest bundle of a prompt by name ({@code YYYY.MM.DD-vNN}, decision 13), for prompts that have no versioned
     * descriptor of their own. The selector of W3-16 replaces this choice.
     */
    public Optional<PromptBundleManifest> newest(String promptKey) {
        return manifests.values().stream()
                .filter(manifest -> manifest.promptKey().equals(promptKey))
                .max(Comparator.comparing(PromptBundleManifest::bundleVersion, PromptBundleCatalog::compareVersionNames));
    }

    public List<PromptBundleManifest> manifests() {
        return List.copyOf(manifests.values());
    }

    static int compareVersionNames(String left, String right) {
        String[] leftParts = left.split("-v", 2);
        String[] rightParts = right.split("-v", 2);
        int date = leftParts[0].compareTo(rightParts[0]);
        if (date != 0 || leftParts.length < 2 || rightParts.length < 2) {
            return date != 0 ? date : left.compareTo(right);
        }
        String[] leftNumber = leftParts[1].split("\\.");
        String[] rightNumber = rightParts[1].split("\\.");
        for (int index = 0; index < Math.max(leftNumber.length, rightNumber.length); index++) {
            int leftValue = index < leftNumber.length ? parse(leftNumber[index]) : 0;
            int rightValue = index < rightNumber.length ? parse(rightNumber[index]) : 0;
            if (leftValue != rightValue) {
                return Integer.compare(leftValue, rightValue);
            }
        }
        return 0;
    }

    private static int parse(String value) {
        try {
            return Integer.parseInt(value);
        }
        catch (NumberFormatException exception) {
            return 0;
        }
    }

    private static String key(String promptKey, String bundleVersion) {
        return promptKey + "@" + bundleVersion;
    }
}
