package io.contexa.demo.shared.web;

import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;

public abstract class AbstractQueryController {

    protected <T> ResponseEntity<T> result(T value) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(value);
    }
}
