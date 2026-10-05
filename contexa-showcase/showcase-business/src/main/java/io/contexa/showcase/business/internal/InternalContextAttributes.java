package io.contexa.showcase.business.internal;

/**
 * Request attributes written by {@link InternalContextFilter} after the internal signature verifies.
 * <p>
 * The engine names are copied here because this module does not depend on Contexa. The contract probes of
 * the Contexa workload assert that the engine reads exactly these names (docs/showcase/연결계약.md).
 */
public final class InternalContextAttributes {

    /** The verified {@link InternalContext} itself, read by the business code of every control. */
    public static final String CONTEXT = InternalContext.class.getName();

    /** Event time of the request. Engine: RequestSecurityContextAttributes.Field.OBSERVED_AT. */
    public static final String OBSERVED_AT = "ctxa.context.observedAt";

    /** Organization scope. Engine: OfficialContextField.ORGANIZATION_ID. */
    public static final String ORGANIZATION_ID = "ctxa.context.organizationId";

    /** Tenant scope. Engine: OfficialContextField.TENANT_ID. */
    public static final String TENANT_ID = "ctxa.context.tenantId";

    /** Decision id stored by the engine as request_id. Engine: RequestInfoExtractor. */
    public static final String REQUEST_ID = "contexa.requestId";

    private InternalContextAttributes() {
    }
}
