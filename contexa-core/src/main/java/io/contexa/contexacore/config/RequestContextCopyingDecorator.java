package io.contexa.contexacore.config;

import org.springframework.core.task.TaskDecorator;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;


public class RequestContextCopyingDecorator implements TaskDecorator {

    @Override
    public Runnable decorate(Runnable runnable) {
        
        RequestAttributes context = RequestContextHolder.getRequestAttributes();

        return () -> {
            try {
                
                if (context != null) {
                    RequestContextHolder.setRequestAttributes(context, true);
                }
                runnable.run();
            } finally {
                
                RequestContextHolder.resetRequestAttributes();
            }
        };
    }
}
