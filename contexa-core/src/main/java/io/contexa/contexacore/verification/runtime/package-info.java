/**
 * Owns transport-neutral official verification orchestration, metric contracts, and runtime ports.
 * Allowed dependencies are Contexa common/core domain contracts and injected repository or transport ports.
 * IAM, web-controller, JDBC/JPA, and Enterprise implementation imports are forbidden.
 * Persistence is owned by injected store/repository ports; this package must not issue SQL.
 */
package io.contexa.contexacore.verification.runtime;
