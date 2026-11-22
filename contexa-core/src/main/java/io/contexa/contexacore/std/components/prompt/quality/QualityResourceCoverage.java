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
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;

/**
 * Which resources and resource classes a case set covers, beside the decisions of the operation of each class
 * (quality P46). The cost of a measurement follows the cases, not the resources protected, so a set covers few
 * resources and is read by class: per class, the roots that must be stopped and those that must be allowed, and the
 * decisions the operation made in the period. A class the operation decided in that has no case, or too few roots on
 * a side for a paired comparison of the class ever to be significant, is a gap.
 *
 * @param cases              the cases of the set
 * @param resources          the distinct resources the cases name
 * @param unidentifiedCases  the cases whose input names no resource
 * @param minimumRoots       the roots a side of a class needs: below it no paired comparison of the rates of the
 *                           class on that side can be significant, whatever the answers
 * @param operationDecisions the decisions of the operation in the period, every class together
 * @param classes            the classes: the shown ones in their order, then those the cases or the decisions have
 * @param topResources       the resources with the most cases, the most first
 */
public record QualityResourceCoverage(int cases, int resources, int unidentifiedCases, int minimumRoots,
                                      long operationDecisions, List<ClassRow> classes,
                                      List<ResourceRow> topResources) {

    /** Whether the operation decides in a class the cases do not cover enough. */
    public enum Gap {
        /** Not a gap: the operation made no decision in the class, or the class has the roots it needs. */
        NONE,
        /** The operation decided in the class and no case has it. */
        NO_CASES,
        /** The operation decided in the class and a side of it has fewer roots than {@code minimumRoots}. */
        FEW_CASES
    }

    /**
     * One class.
     *
     * @param resourceClass      the class, or {@link QualityCaseResource#UNCLASSIFIED}
     * @param cases              the cases of the class
     * @param stopCases          those that must be stopped
     * @param allowCases         those that must be allowed
     * @param stopRoots          the distinct roots of the cases that must be stopped
     * @param allowRoots         the distinct roots of the cases that must be allowed
     * @param resources          the distinct resources the cases of the class name
     * @param operationDecisions the decisions of the operation in the class in the period
     * @param gap                whether the operation decides in the class without enough cases
     */
    public record ClassRow(String resourceClass, int cases, int stopCases, int allowCases, int stopRoots,
                           int allowRoots, int resources, long operationDecisions, Gap gap) {
    }

    /**
     * One resource.
     *
     * @param resource        the resource the cases name
     * @param httpMethod      its HTTP method, as the first case naming it that gives one gives it; null when none does
     * @param urlTemplate     its URL template, as the first case naming it that gives one gives it; null when none does
     * @param resourceClasses the classes its cases are under, in the order of the classes
     * @param cases           the cases naming it
     * @param stopCases       those that must be stopped
     * @param allowCases      those that must be allowed
     * @param roots           the distinct roots of its cases
     */
    public record ResourceRow(String resource, String httpMethod, String urlTemplate, List<String> resourceClasses,
                              int cases, int stopCases, int allowCases, int roots) {

        public ResourceRow {
            resourceClasses = List.copyOf(resourceClasses);
        }
    }

    public QualityResourceCoverage {
        classes = List.copyOf(classes);
        topResources = List.copyOf(topResources);
    }

    /** The class, or empty when it is not shown. */
    public Optional<ClassRow> find(String resourceClass) {
        return classes.stream().filter(row -> row.resourceClass().equals(resourceClass)).findFirst();
    }

    /** The classes that are gaps, in the order of the classes. */
    public List<ClassRow> gaps() {
        return classes.stream().filter(row -> row.gap() != Gap.NONE).toList();
    }

    /**
     * The smallest number of roots on which the one-sided exact sign test of the paired comparison can reject chance
     * at the level: with fewer, even every root turning the same way is not significant (5 at the 5% level).
     */
    public static int minimumRoots(double significance) {
        if (!(significance > 0 && significance < 1)) {
            throw new IllegalArgumentException("The significance level lies between 0 and 1: " + significance);
        }
        int roots = 1;
        while (QualityStatistics.signTestTail(roots, roots) > significance) {
            roots++;
        }
        return roots;
    }

    /**
     * The coverage of the cases.
     *
     * @param cases              the cases of the set
     * @param resourceOf         the resource and class of a case
     * @param operationDecisions the decisions of the operation in the period by class, the unclassified under
     *                           {@link QualityCaseResource#UNCLASSIFIED}
     * @param shown              the classes shown even when nothing has them, in their order
     * @param minimumRoots       the roots a side of a class needs ({@link #minimumRoots(double)})
     * @param top                how many resources the list of the most covered holds
     */
    public static QualityResourceCoverage of(Collection<QualityCase> cases,
                                             Function<QualityCase, QualityCaseResource> resourceOf,
                                             Map<String, Long> operationDecisions, List<String> shown,
                                             int minimumRoots, int top) {
        Objects.requireNonNull(resourceOf, "resourceOf");
        Map<String, List<QualityCase>> byClass = new LinkedHashMap<>();
        Map<String, List<QualityCase>> byResource = new LinkedHashMap<>();
        Map<String, QualityCaseResource> firstOfResource = new LinkedHashMap<>();
        Map<String, Set<String>> resourceClasses = new LinkedHashMap<>();
        Map<String, Set<String>> classResources = new LinkedHashMap<>();
        int unidentified = 0;
        for (QualityCase item : cases) {
            QualityCaseResource resource = Objects.requireNonNullElse(resourceOf.apply(item), QualityCaseResource.NONE);
            byClass.computeIfAbsent(resource.group(), group -> new ArrayList<>()).add(item);
            if (resource.resource() == null) {
                unidentified++;
                continue;
            }
            byResource.computeIfAbsent(resource.resource(), key -> new ArrayList<>()).add(item);
            firstOfResource.merge(resource.resource(), resource, (kept, next) -> new QualityCaseResource(
                    kept.resourceClass(), kept.resource(),
                    kept.httpMethod() != null ? kept.httpMethod() : next.httpMethod(),
                    kept.urlTemplate() != null ? kept.urlTemplate() : next.urlTemplate()));
            resourceClasses.computeIfAbsent(resource.resource(), key -> new HashSet<>()).add(resource.group());
            classResources.computeIfAbsent(resource.group(), key -> new HashSet<>()).add(resource.resource());
        }
        Map<String, Long> decisions = new LinkedHashMap<>();
        long decided = 0;
        if (operationDecisions != null) {
            for (Map.Entry<String, Long> entry : operationDecisions.entrySet()) {
                long count = entry.getValue() != null ? entry.getValue() : 0;
                if (count > 0) {
                    decisions.merge(entry.getKey() != null ? entry.getKey() : QualityCaseResource.UNCLASSIFIED, count,
                            Long::sum);
                    decided += count;
                }
            }
        }
        Set<String> seen = new LinkedHashSet<>(byClass.keySet());
        seen.addAll(decisions.keySet());
        List<String> order = QualityCaseResource.order(shown, seen);

        List<ClassRow> rows = new ArrayList<>();
        for (String group : order) {
            List<QualityCase> members = byClass.getOrDefault(group, List.of());
            int stopCases = (int) members.stream().filter(QualityCase::shouldStop).count();
            int[] roots = QualityResourceClassScore.roots(members);
            long operation = decisions.getOrDefault(group, 0L);
            Gap gap = operation == 0 ? Gap.NONE : members.isEmpty() ? Gap.NO_CASES
                    : roots[0] < minimumRoots || roots[1] < minimumRoots ? Gap.FEW_CASES : Gap.NONE;
            rows.add(new ClassRow(group, members.size(), stopCases, members.size() - stopCases, roots[0], roots[1],
                    classResources.getOrDefault(group, Set.of()).size(), operation, gap));
        }

        List<ResourceRow> resources = new ArrayList<>();
        for (Map.Entry<String, List<QualityCase>> entry : byResource.entrySet()) {
            List<QualityCase> members = entry.getValue();
            QualityCaseResource first = firstOfResource.get(entry.getKey());
            int stopCases = (int) members.stream().filter(QualityCase::shouldStop).count();
            Set<String> roots = new HashSet<>();
            members.forEach(item -> roots.add(item.rootKey()));
            Set<String> under = resourceClasses.get(entry.getKey());
            resources.add(new ResourceRow(entry.getKey(), first.httpMethod(), first.urlTemplate(),
                    order.stream().filter(under::contains).toList(), members.size(), stopCases,
                    members.size() - stopCases, roots.size()));
        }
        resources.sort(Comparator.comparingInt(ResourceRow::cases).reversed().thenComparing(ResourceRow::resource));
        return new QualityResourceCoverage(cases.size(), byResource.size(), unidentified, minimumRoots, decided, rows,
                resources.subList(0, Math.min(Math.max(top, 0), resources.size())));
    }
}
