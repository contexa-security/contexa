package io.contexa.demo.observation.provider.service;

public interface ProviderBodySanitizer {

    String sanitize(byte[] body);
}
