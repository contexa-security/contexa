package io.contexa.contexacommon.domain.request;

import io.contexa.contexacommon.domain.context.IAMContext;
import lombok.Getter;


@Getter
public class IAMRequest<T extends IAMContext> extends AIRequest<T> {

    public IAMRequest(T context, String promptTemplate) {
        super(context, promptTemplate, null);
    }

    public IAMRequest(T context, String promptTemplate, RequestPriority priority, RequestType requestType) {
        super(context, promptTemplate, priority, requestType);
    }
}