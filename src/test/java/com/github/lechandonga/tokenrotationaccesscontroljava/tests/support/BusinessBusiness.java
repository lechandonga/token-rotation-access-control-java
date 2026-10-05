package com.github.lechandonga.tokenrotationaccesscontroljava.tests.support;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 标注测试类对应的业务模块名称，供测试日志展示。
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
public @interface BusinessBusiness {

    String value();
}
