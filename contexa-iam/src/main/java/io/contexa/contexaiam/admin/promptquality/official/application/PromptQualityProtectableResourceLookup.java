package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexaiam.admin.promptquality.official.application.ProtectableResourceDescriptor;

import java.util.Optional;

public interface PromptQualityProtectableResourceLookup {

    Optional<ProtectableResourceDescriptor> findBestMatch(String resourceUrl, String resourceId, String httpMethod);
}
