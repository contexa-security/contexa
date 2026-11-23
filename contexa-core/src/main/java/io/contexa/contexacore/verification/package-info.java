/**
 * Owns framework-neutral public contracts and domain models for the sealed evidence of a decision: its capture, the
 * sealed package, its inspection and its replay.
 * Java platform types and stable core contracts may be imported; IAM, web, servlet, and Enterprise
 * implementation packages are forbidden.
 * Persistence is expressed only through core ports; SQL, ORM, repository adapters, and transaction
 * implementation details belong to downstream adapter modules.
 * This package never creates or mutates host authentication, authorization, or security-filter state.
 */
package io.contexa.contexacore.verification;