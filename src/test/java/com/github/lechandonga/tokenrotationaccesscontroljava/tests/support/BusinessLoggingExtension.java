package com.github.lechandonga.tokenrotationaccesscontroljava.tests.support;

import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.TestExecutionExceptionHandler;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 业务用例日志扩展：在测试日志中输出业务模块、用例名称与执行结果，
 * 并在每个业务类结束时输出通过/失败统计，便于从日志识别覆盖范围。
 *
 * <p>通过 JUnit 5 自动注册（见
 * META-INF/services/org.junit.jupiter.api.extension.Extension）。
 */
public class BusinessLoggingExtension implements BeforeAllCallback, TestExecutionExceptionHandler,
        AfterAllCallback {

    private record Counters(AtomicInteger passed, AtomicInteger failed) {
    }

    private static final Map<String, Counters> SUMMARY = new ConcurrentHashMap<>();

    @Override
    public void beforeAll(ExtensionContext context) {
        String business = businessName(context);
        SUMMARY.computeIfAbsent(business, key -> new Counters(new AtomicInteger(), new AtomicInteger()));
        System.out.println();
        System.out.println("========== 业务模块: " + business + " 开始 ==========");
    }

    @Override
    public void handleTestExecutionException(ExtensionContext context, Throwable throwable) throws Throwable {
        business(context).failed.incrementAndGet();
        System.out.println("[失败] 用例: " + context.getDisplayName() + " -> "
                + throwable.getClass().getSimpleName() + ": " + throwable.getMessage());
        throw throwable;
    }

    @Override
    public void afterAll(ExtensionContext context) {
        String business = businessName(context);
        Counters counters = business(context);
        int total = counters.passed.get() + counters.failed.get();
        System.out.println("---------- 业务模块: " + business + " 结束 | 用例数: " + total
                + " | 通过: " + counters.passed.get() + " | 失败: " + counters.failed.get()
                + " ----------");
        System.out.println();
    }

    /**
     * 在测试正常通过后记录日志。Junit 的 {@code TestExecutionExceptionHandler} 只在异常时回调，
     * 成功用例由 {@link BusinessTestWatcher} 通知到本扩展。
     */
    void markPassed(String business, String displayName) {
        Counters counters = SUMMARY.computeIfAbsent(business,
                key -> new Counters(new AtomicInteger(), new AtomicInteger()));
        counters.passed.incrementAndGet();
        System.out.println("[通过] 用例: " + displayName);
    }

    private Counters business(ExtensionContext context) {
        return SUMMARY.get(businessName(context));
    }

    private static String businessName(ExtensionContext context) {
        Class<?> testClass = context.getRequiredTestClass();
        BusinessBusiness annotation = testClass.getAnnotation(BusinessBusiness.class);
        return annotation == null ? testClass.getSimpleName() : annotation.value();
    }
}
