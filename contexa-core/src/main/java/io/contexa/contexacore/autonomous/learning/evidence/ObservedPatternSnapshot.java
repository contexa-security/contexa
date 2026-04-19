package io.contexa.contexacore.autonomous.learning.evidence;

import java.util.List;

public record ObservedPatternSnapshot(
        List<String> networks,
        List<String> accessHours,
        List<String> accessDays,
        List<String> browsers,
        List<String> operatingSystems,
        List<String> pathFamilies,
        List<String> authenticationTypes,
        List<String> actionFamilies,
        List<String> resourceFamilies) {

    public ObservedPatternSnapshot {
        networks = immutable(networks);
        accessHours = immutable(accessHours);
        accessDays = immutable(accessDays);
        browsers = immutable(browsers);
        operatingSystems = immutable(operatingSystems);
        pathFamilies = immutable(pathFamilies);
        authenticationTypes = immutable(authenticationTypes);
        actionFamilies = immutable(actionFamilies);
        resourceFamilies = immutable(resourceFamilies);
    }

    private static List<String> immutable(List<String> values) {
        return values == null ? List.of() : List.copyOf(values);
    }
}
