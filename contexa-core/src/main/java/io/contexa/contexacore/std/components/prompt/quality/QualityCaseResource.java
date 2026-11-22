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

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * What a labelled case decides on (quality P46): the protected resource of its request and the class of that resource.
 * The measurement is of a prompt version, not of a resource; the resource enters as the input of a case. Its class is
 * the one the decision row of the same input gets, so the cases of a class stand beside the decisions of the operation
 * of that class. The quality package reads no engine: the class and the resource are worked out where the engine is
 * and given here.
 *
 * @param resourceClass the class of the resource, such as CRITICAL or SENSITIVE; null when the input gives none
 * @param resource      the protected resource the request reached, such as the protected method's id; null when the
 *                      input names none
 * @param httpMethod    the HTTP method of the protected resource, or null
 * @param urlTemplate   the URL template of the protected resource, or null
 */
public record QualityCaseResource(String resourceClass, String resource, String httpMethod, String urlTemplate) {

    /** The group of the cases, and of the decisions, whose resource has no class. */
    public static final String UNCLASSIFIED = "UNCLASSIFIED";

    /** A case whose input gives neither a class nor a resource. */
    public static final QualityCaseResource NONE = new QualityCaseResource(null, null, null, null);

    public QualityCaseResource {
        resourceClass = blankToNull(resourceClass);
        resource = blankToNull(resource);
        httpMethod = blankToNull(httpMethod);
        urlTemplate = blankToNull(urlTemplate);
    }

    /** The class the case is counted under: its class, or {@link #UNCLASSIFIED}. */
    public String group() {
        return resourceClass != null ? resourceClass : UNCLASSIFIED;
    }

    /**
     * The classes to show: the given ones in their order, also when nothing has them, then the other classes seen, by
     * name, and the unclassified last.
     */
    static List<String> order(List<String> shown, Collection<String> seen) {
        Set<String> ordered = new LinkedHashSet<>(shown);
        Set<String> others = new TreeSet<>(seen);
        others.removeAll(ordered);
        boolean unclassified = others.remove(UNCLASSIFIED) | ordered.remove(UNCLASSIFIED);
        ordered.addAll(others);
        if (unclassified) {
            ordered.add(UNCLASSIFIED);
        }
        return new ArrayList<>(ordered);
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }
}
