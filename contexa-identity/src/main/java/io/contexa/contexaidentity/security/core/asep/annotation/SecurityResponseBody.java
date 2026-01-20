package io.contexa.contexaidentity.security.core.asep.annotation;

import org.springframework.web.bind.annotation.ResponseBody;

import java.lang.annotation.*;


@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@ResponseBody 
public @interface SecurityResponseBody {
}
