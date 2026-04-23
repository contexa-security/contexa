package io.contexa.contexacommon.autoconfigure.capability;

import java.util.List;

public interface CapabilityContributor {

    String contributorName();

    List<ContexaCapability> capabilities();

    List<CapabilityCheckResult> check();
}
