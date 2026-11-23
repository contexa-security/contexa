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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * The measurements Contexa took of its own versions on the default case set before a release, shipped with the
 * product (plan 3.4). An installation uses one only for the version with the same content, on the same case set
 * version, under the same server settings that change an answer; any other installation measures the version itself.
 * Without the resource there is none.
 *
 * <p>The document, of format {@value #DOCUMENT_FORMAT}:
 * <pre>
 * {"format": 1, "measurements": [{
 *   "prompt": "cortex.security-decision", "release": "2026.11.18-v1.0",
 *   "versionContentHash": "&lt;the content hash of the version&gt;",
 *   "caseSetVersion": "&lt;the version of the default case set&gt;",
 *   "settingsHash": "&lt;the hash of the server settings that change an answer&gt;",
 *   "modelSetting": "settings=&lt;the same hash&gt;;models=&lt;the models that answered&gt;",
 *   "repeats": 3, "measuredAt": "2026-11-30T00:00:00Z",
 *   "answers": [{"caseKey": "...", "run": 1, "firstAction": "BLOCK", "finalAction": "BLOCK", "reasked": false,
 *     "decidedWithoutModel": false, "citedFacts": 3, "accurateCitedFacts": 3, "decisionMillis": 7000,
 *     "answerTokens": 120, "measurementFailed": false, "failureReason": null}]}]}
 * </pre>
 */
public final class QualityShippedMeasurements {

    /** Where the product ships the measurements of its versions of the security decision. */
    public static final String CONTEXA_RESOURCE =
            "prompt-quality/cortex.security-decision/contexa-shipped-measurements.json";

    /** The version of the form of the document this reader reads. */
    public static final int DOCUMENT_FORMAT = 1;

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final QualityShippedMeasurements NONE = new QualityShippedMeasurements(List.of());

    /**
     * One shipped measurement.
     *
     * @param release            the product release of the version, as a person reads it
     * @param versionContentHash the content hash of the version it measured
     * @param caseSetVersion     the version of the default case set it ran on
     * @param settingsHash       the hash of the server settings that change an answer, as it ran
     * @param modelSetting       the model setting it names: the settings and the models that answered
     */
    public record Shipped(String prompt, String release, String versionContentHash, String caseSetVersion,
                          String settingsHash, String modelSetting, int repeats, Instant measuredAt,
                          List<QualityAnswer> answers) {

        public Shipped {
            Objects.requireNonNull(prompt, "prompt");
            Objects.requireNonNull(versionContentHash, "versionContentHash");
            Objects.requireNonNull(caseSetVersion, "caseSetVersion");
            Objects.requireNonNull(settingsHash, "settingsHash");
            Objects.requireNonNull(modelSetting, "modelSetting");
            answers = List.copyOf(answers);
        }

        /** The measurement as the gate reads it, under the name the version has in this installation. */
        public QualityMeasurement measurement(String versionName) {
            return new QualityMeasurement(versionName, modelSetting, caseSetVersion, repeats, answers);
        }
    }

    private final List<Shipped> measurements;

    private QualityShippedMeasurements(List<Shipped> measurements) {
        this.measurements = List.copyOf(measurements);
    }

    /** No shipped measurement. */
    public static QualityShippedMeasurements none() {
        return NONE;
    }

    /** The measurements the product ships; none when the product ships no such resource. */
    public static QualityShippedMeasurements contexa() {
        return fromResource(CONTEXA_RESOURCE);
    }

    /** The measurements of the resource; none when there is no such resource. */
    public static QualityShippedMeasurements fromResource(String resource) {
        try (InputStream in = QualityShippedMeasurements.class.getClassLoader().getResourceAsStream(resource)) {
            if (in == null) {
                return NONE;
            }
            return read(in);
        }
        catch (IOException exception) {
            throw new UncheckedIOException(exception);
        }
    }

    /** The measurements of the document; a document of another format is refused. */
    public static QualityShippedMeasurements read(InputStream json) throws IOException {
        JsonNode document = JSON.readTree(json);
        if (document == null || document.path("format").asInt(-1) != DOCUMENT_FORMAT) {
            throw new IllegalArgumentException("The shipped measurements are not of format " + DOCUMENT_FORMAT);
        }
        List<Shipped> read = new ArrayList<>();
        for (JsonNode item : document.path("measurements")) {
            List<QualityAnswer> answers = new ArrayList<>();
            for (JsonNode answer : item.path("answers")) {
                answers.add(new QualityAnswer(answer.path("caseKey").asText(null), answer.path("run").asInt(0),
                        QualityAction.parse(answer.path("firstAction").asText(null)),
                        QualityAction.parse(answer.path("finalAction").asText(null)),
                        answer.path("reasked").asBoolean(false), answer.path("decidedWithoutModel").asBoolean(false),
                        answer.path("citedFacts").asInt(0), answer.path("accurateCitedFacts").asInt(0),
                        answer.hasNonNull("decisionMillis") ? answer.path("decisionMillis").asLong() : null,
                        answer.hasNonNull("answerTokens") ? answer.path("answerTokens").asInt() : null,
                        answer.path("measurementFailed").asBoolean(false), answer.path("failureReason").asText(null)));
            }
            read.add(new Shipped(item.path("prompt").asText(null), item.path("release").asText(null),
                    item.path("versionContentHash").asText(null), item.path("caseSetVersion").asText(null),
                    item.path("settingsHash").asText(null), item.path("modelSetting").asText(null),
                    item.path("repeats").asInt(0),
                    item.hasNonNull("measuredAt") ? Instant.parse(item.path("measuredAt").asText()) : null, answers));
        }
        return new QualityShippedMeasurements(read);
    }

    public List<Shipped> all() {
        return measurements;
    }

    /**
     * The shipped measurement of the version with that content, on that case set version, under those settings; empty
     * when the product shipped none taken the same way.
     */
    public Optional<Shipped> find(String prompt, String versionContentHash, String caseSetVersion,
                                  String settingsHash) {
        return measurements.stream()
                .filter(shipped -> shipped.prompt().equals(prompt))
                .filter(shipped -> shipped.versionContentHash().equals(versionContentHash))
                .filter(shipped -> shipped.caseSetVersion().equals(caseSetVersion))
                .filter(shipped -> shipped.settingsHash().equals(settingsHash))
                .findFirst();
    }
}
