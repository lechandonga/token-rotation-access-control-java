package com.github.lechandonga.tokenrotationaccesscontroljava.tests.support;

import java.util.Optional;
import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.AfterTestExecutionCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 统一输出“业务模块 -> 用例 -> 结果”的测试日志，运行测试即可直观看出覆盖范围。
 */
public class BusinessLoggingExtension implements
        BeforeAllCallback, BeforeEachCallback, AfterTestExecutionCallback, AfterAllCallback {

    private int passed;
    private int failed;

    @Override
    public void beforeAll(ExtensionContext context) {
        passed = 0;
        failed = 0;
        Logger log = LoggerFactory.getLogger(context.getRequiredTestClass());
        log.info("====== 业务模块: {} | 测试类: {} ======",
                businessName(context), context.getRequiredTestClass().getSimpleName());
    }

    @Override
    public void beforeEach(ExtensionContext context) {
        LoggerFactory.getLogger(context.getRequiredTestClass())
                .info("--> 开始用例: {}", context.getDisplayName());
    }

    @Override
    public void afterTestExecution(ExtensionContext context) {
        Logger log = LoggerFactory.getLogger(context.getRequiredTestClass());
        Optional<Throwable> error = context.getExecutionException();
        if (error.isPresent()) {
            failed++;
            log.info("<-- 用例结果: 失败 | {} | 原因: {}", context.getDisplayName(),
                    String.valueOf(error.get().getMessage()));
        } else {
            passed++;
            log.info("<-- 用例结果: 通过 | {}", context.getDisplayName());
        }
    }

    @Override
    public void afterAll(ExtensionContext context) {
        LoggerFactory.getLogger(context.getRequiredTestClass())
                .info("====== 业务模块: {} 汇总 | 用例总数: {} | 通过: {} | 失败: {} ======",
                        businessName(context), passed + failed, passed, failed);
    }

    private String businessName(ExtensionContext context) {
        Business annotation = context.getRequiredTestClass().getAnnotation(Business.class);
        return annotation != null ? annotation.value() : "未标注业务";
    }
}
