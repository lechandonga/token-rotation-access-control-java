package com.github.lechandonga.tokenrotationaccesscontroljava.tests.support;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/** 标注测试类覆盖的业务模块，供日志扩展输出业务覆盖情况。 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface Business {
    String value();
}
