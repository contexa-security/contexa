/*
 * Copyright 2026 The Contexa Project
 *
 * Licensed under the Apache License, Version 2.0.
 */
package io.contexa.contexaiam.resource;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

class StaticAssetReferenceContractTest {

    private static final Path RESOURCE_ROOT = Path.of("src", "main", "resources");
    private static final Path TEMPLATE_ROOT = RESOURCE_ROOT.resolve("templates");
    private static final Path STATIC_ROOT = RESOURCE_ROOT.resolve("static");
    private static final Pattern ASSET_ATTRIBUTE = Pattern.compile(
            "(?i)(?:th:)?(?:href|src)\\s*=\\s*([\"'])(.*?)\\1");
    private static final Pattern ASSET_EXTENSION = Pattern.compile(
            ".*\\.(?:css|js|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|map)$",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern LEGACY_NAMESPACE = Pattern.compile(
            "^/(?:css|js|img|images|fonts)/");

    @Test
    void everyTemplateAssetUsesContexaNamespaceAndExistsOnClasspath() throws IOException {
        List<Path> templates;
        try (Stream<Path> paths = Files.walk(TEMPLATE_ROOT)) {
            templates = paths.filter(path -> path.toString().endsWith(".html")).toList();
        }

        List<String> violations = new ArrayList<>();
        int assetReferenceCount = 0;
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        for (Path template : templates) {
            Matcher matcher = ASSET_ATTRIBUTE.matcher(Files.readString(template));
            while (matcher.find()) {
                String value = matcher.group(2).trim();
                if (isExternal(value)) {
                    if (hasContexaNamespaceInsideExternalUrl(value)) {
                        violations.add(template + " -> corrupted external URL: " + value);
                    }
                    continue;
                }

                String path = extractLocalPath(value);
                if (path == null || !ASSET_EXTENSION.matcher(path).matches()) {
                    continue;
                }
                assetReferenceCount++;
                if (!path.startsWith("/")) {
                    violations.add(template + " -> relative asset path: " + value);
                    continue;
                }
                if (LEGACY_NAMESPACE.matcher(path).find()) {
                    violations.add(template + " -> legacy asset namespace: " + path);
                    continue;
                }
                if (classLoader.getResource("static" + path) == null) {
                    violations.add(template + " -> missing classpath asset: " + path);
                }
            }
        }

        assertThat(templates).isNotEmpty();
        assertThat(assetReferenceCount).isPositive();
        assertThat(violations).as("invalid HTML asset references").isEmpty();
        assertLegacyStaticDirectoriesRemoved();
    }

    private boolean isExternal(String value) {
        return value.startsWith("http://") || value.startsWith("https://") || value.startsWith("//");
    }

    private boolean hasContexaNamespaceInsideExternalUrl(String value) {
        try {
            String path = URI.create(value.startsWith("//") ? "https:" + value : value).getPath();
            return path != null && path.matches(".*/contexa/(?:css|js|img|images|fonts)/.*");
        } catch (IllegalArgumentException ignored) {
            return false;
        }
    }

    private String extractLocalPath(String value) {
        String path;
        if (value.startsWith("@{")) {
            path = value.substring(2);
            path = path.substring(0, firstDelimiter(path, '?', '(', '}'));
        } else {
            path = value;
            path = path.substring(0, firstDelimiter(path, '?', '#'));
        }
        return path.trim();
    }

    private int firstDelimiter(String value, char... delimiters) {
        int result = value.length();
        for (char delimiter : delimiters) {
            int index = value.indexOf(delimiter);
            if (index >= 0) {
                result = Math.min(result, index);
            }
        }
        return result;
    }

    private void assertLegacyStaticDirectoriesRemoved() {
        List<String> legacyDirectories = List.of("css", "js", "img", "images", "fonts");
        assertThat(legacyDirectories)
                .noneMatch(directory -> Files.isDirectory(STATIC_ROOT.resolve(directory.toLowerCase(Locale.ROOT))));
    }
}
