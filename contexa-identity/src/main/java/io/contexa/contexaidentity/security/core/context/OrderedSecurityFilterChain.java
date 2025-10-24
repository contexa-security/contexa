package io.contexa.contexaidentity.security.core.context;

import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.Ordered;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.List;

/**
 * {@code OrderedSecurityFilterChain}은 {@link SecurityFilterChain}에 {@link Ordered} 기능을 추가하여,
 * 다수의 보안 필터 체인을 우선순위(order) 기준으로 정렬 및 적용할 수 있게 해주는 클래스입니다.
 *
 * <p>Spring Security는 여러 개의 {@link SecurityFilterChain}을 구성할 수 있도록 지원하며,
 * 이때 각 체인이 적용되는 순서를 명확히 지정하기 위해 {@link Ordered} 인터페이스를 사용할 수 있습니다.
 * 이 클래스는 {@link DefaultSecurityFilterChain}을 내부적으로 위임(delegate)받아 처리하며,
 * 사용자 지정 순서를 지정할 수 있도록 {@code order} 값을 필드로 보유합니다.
 *
 * <h2>사용 예시:</h2>
 * <pre>{@code
 *  OrderedSecurityFilterChain chain = new OrderedSecurityFilterChain(
 *      1,
 *      new AntPathRequestMatcher("/api/**"),
 *      List.of(new CustomFilter())
 *  );
 * }</pre>
 *
 * <p>{@code @Order} 애노테이션 대신 프로그래밍 방식으로 우선순위를 지정하고자 할 때 유용합니다.
 *
 * @soowon.jung
 */
public class OrderedSecurityFilterChain implements SecurityFilterChain, Ordered {

    /**
     * 요청 매칭 및 필터 체인 처리를 위임하는 기본 보안 필터 체인.
     */
    private final DefaultSecurityFilterChain delegate;

    /**
     * 이 보안 필터 체인의 실행 순서를 나타내는 정수 값.
     */
    private final int order;

    /**
     * 지정된 {@code order}, {@code RequestMatcher}, {@code Filter} 목록을 사용하여
     * 새로운 {@code OrderedSecurityFilterChain} 인스턴스를 생성합니다.
     *
     * @param order   필터 체인의 우선순위. 낮을수록 먼저 적용됩니다.
     * @param matcher 이 필터 체인이 적용될 요청을 매칭하기 위한 조건.
     * @param filters 요청 처리 시 적용할 필터 목록.
     */
    public OrderedSecurityFilterChain(int order, RequestMatcher matcher, List<Filter> filters) {
        this.delegate = new DefaultSecurityFilterChain(matcher, filters);
        this.order = order;
    }

    @Override
    public int getOrder() {
        return order;
    }

    @Override
    public boolean matches(HttpServletRequest request) {
        return delegate.matches(request);
    }

    @Override
    public List<Filter> getFilters() {
        return delegate.getFilters();
    }
}


