package io.contexa.contexacommon.domain.request;

import io.contexa.contexacommon.domain.context.IAMContext;
import lombok.Getter;

/**
 * IAM AI 요청 클래스
 * AI Core 요청을 확장하여 IAM 특화 기능을 제공
 * 
 * @param <T> IAM 컨텍스트 타입
 */
@Getter
public class IAMRequest<T extends IAMContext> extends AIRequest<T> {

    public IAMRequest(T context, String promptTemplate) {
        super(context, promptTemplate, null);
    }

    public IAMRequest(T context, String promptTemplate, RequestPriority priority, RequestType requestType) {
        super(context, promptTemplate, priority, requestType);
    }
}