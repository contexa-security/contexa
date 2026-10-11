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
package io.contexa.contexacore.verification.runtime;

import io.contexa.contexacore.verification.metric.OfficialPromptQualityNarrativeCatalog;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * W1-16 (V-16): the core resolves its own messages from the core bundle. The core's test classpath has no IAM module,
 * so a key missing from the core bundle fails here as it would in an application that uses the core alone.
 */
class OfficialVerificationMessageResolverTest {

    private static final Pattern MESSAGE_KEY = Pattern.compile(
            "\"((?:enterprise\\.pqa|verification\\.finalPrompt)\\.[\\w.-]*[\\w-])\"");
    private static final Pattern CHECK_NARRATIVE = Pattern.compile("checkNarrative\\(\"(\\w+)\"\\)");
    private static final List<String> METRIC_CODES = List.of(
            "EIR", "CCR", "CCSR", "PFR", "MTR", "COR", "RAP", "RPI", "BMA", "USNS", "BSR", "PRE", "OTHER");

    @ParameterizedTest
    @ValueSource(strings = {"ko", "en"})
    void everyMessageKeyTheCoreNamesResolvesFromTheCoreBundle(String language) throws IOException {
        OfficialVerificationMessageResolver resolver =
                OfficialVerificationMessageResolver.classpath(Locale.forLanguageTag(language));
        Set<String> keys = keysNamedInCoreSources();

        assertThat(keys).hasSizeGreaterThan(100);
        for (String key : keys) {
            assertThat(resolver.resolve(key, "a", "b", "c", "d")).as(key).isNotBlank();
        }
    }

    @Test
    void theNarrativeCatalogComposesOnlyKeysOfTheCoreBundle() throws IOException {
        String catalogSource = Files.readString(Path.of(
                "src/main/java/io/contexa/contexacore/verification/metric/OfficialPromptQualityNarrativeCatalog.java"),
                StandardCharsets.UTF_8);
        Matcher checks = CHECK_NARRATIVE.matcher(catalogSource);
        List<String> checkKeys = checks.results().map(result -> result.group(1)).distinct().toList();
        assertThat(checkKeys).isNotEmpty();
        for (Locale locale : List.of(Locale.KOREAN, Locale.ENGLISH)) {
            OfficialVerificationMessageResolver resolver = OfficialVerificationMessageResolver.classpath(locale);
            OfficialPromptQualityNarrativeCatalog catalog = new OfficialPromptQualityNarrativeCatalog(resolver);
            for (String code : METRIC_CODES) {
                assertThat(catalog.metricName(code)).as(code).isNotBlank();
                assertThat(catalog.metricPurpose(code)).as(code).isNotBlank();
                assertThat(catalog.metricImpact(code)).as(code).isNotBlank();
                assertThat(catalog.metricDefaultAction(code)).as(code).isNotBlank();
                assertThat(catalog.metricDefaultReverify(code)).as(code).isNotBlank();
            }
            for (String check : checkKeys) {
                for (String part : List.of("subject", "owner", "cause", "action", "reverify")) {
                    String key = "enterprise.pqa.officialNarrative.check." + check + "." + part;
                    assertThat(resolver.resolve(key, "a", "b")).as(key).isNotBlank();
                }
            }
        }
    }

    /** Whole message keys named in the core's main sources; prefixes the core composes keys from end with a dot. */
    private static Set<String> keysNamedInCoreSources() throws IOException {
        Set<String> keys = new TreeSet<>();
        try (Stream<Path> files = Files.walk(Path.of("src/main/java"))) {
            for (Path file : files.filter(path -> path.toString().endsWith(".java")).toList()) {
                Matcher matcher = MESSAGE_KEY.matcher(Files.readString(file, StandardCharsets.UTF_8));
                while (matcher.find()) {
                    keys.add(matcher.group(1));
                }
            }
        }
        return keys;
    }
}
