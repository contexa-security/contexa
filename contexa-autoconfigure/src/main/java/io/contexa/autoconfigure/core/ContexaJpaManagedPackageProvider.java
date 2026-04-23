package io.contexa.autoconfigure.core;

import java.util.Collection;

/**
 * Contributes Contexa-owned JPA entity packages to the dedicated Contexa
 * persistence unit without extending the host application's entity scan.
 */
@FunctionalInterface
public interface ContexaJpaManagedPackageProvider {

    Collection<String> getPackagesToScan();
}
