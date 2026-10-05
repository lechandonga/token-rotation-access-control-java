package com.github.lechandonga.tokenrotationaccesscontroljava.tests.support;

import org.junit.jupiter.api.extension.AfterTestExecutionCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

/**
 * 成功用例的日志回调：异常用例由 {@link BusinessLoggingExtension} 处理。
 */
public class BusinessTestWatcher implements AfterTestExecutionCallback {

    private final BusinessLoggingExtension loggingExtension = new BusinessLoggingExtension();

    @Override
    public void afterTestExecution(ExtensionContext context) {
        if (context.getExecutionException().isEmpty()) {
            Class<?> testClass = context.getRequiredTestClass();
            BusinessBusiness annotation = testClass.getAnnotation(BusinessBusiness.class);
            String business = annotation == null ? testClass.getSimpleName() : annotation.value();
            loggingExtension.markPassed(business, context.getDisplayName());
        }
    }
}
