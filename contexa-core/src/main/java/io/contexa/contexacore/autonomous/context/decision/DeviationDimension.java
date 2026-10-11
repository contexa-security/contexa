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
package io.contexa.contexacore.autonomous.context.decision;

/**
 * A dimension on which a request is compared with the usual behaviour, in the order the prompt lists them (W2-5).
 * What may explain a difference follows the review's definition (B2): a valid approval or ticket that covers the work
 * explains the dimensions of the work, a registered trip explains the network, nothing explains the device or the
 * login method.
 */
public enum DeviationDimension {

    TIME("time", "DEVIATION_TIME", Explainer.COVERING_RECORD),
    DAY("day", "DEVIATION_DAY", Explainer.COVERING_RECORD),
    NETWORK("network", "DEVIATION_NETWORK", Explainer.TRAVEL),
    DEVICE("device", "DEVIATION_DEVICE", Explainer.NONE),
    LOGIN_METHOD("login method", "DEVIATION_LOGIN_METHOD", Explainer.NONE),
    TARGET("target", "DEVIATION_TARGET", Explainer.COVERING_RECORD),
    ACTION("action", "DEVIATION_ACTION", Explainer.COVERING_RECORD),
    RESOURCE_CLASS("class", "DEVIATION_RESOURCE_CLASS", Explainer.COVERING_RECORD),
    SIZE("size", "DEVIATION_SIZE", Explainer.COVERING_RECORD),
    RATE("rate", "DEVIATION_RATE", Explainer.COVERING_RECORD);

    /** What can explain a difference on a dimension. */
    public enum Explainer {
        COVERING_RECORD,
        TRAVEL,
        NONE
    }

    private final String label;
    private final String code;
    private final Explainer explainer;

    DeviationDimension(String label, String code, Explainer explainer) {
        this.label = label;
        this.code = code;
        this.explainer = explainer;
    }

    /** The dimension's name in the prompt ({@code time}, {@code login method}). */
    public String label() {
        return label;
    }

    /** The reason code a decision cites for a difference on this dimension. */
    public String code() {
        return code;
    }

    public Explainer explainer() {
        return explainer;
    }
}
