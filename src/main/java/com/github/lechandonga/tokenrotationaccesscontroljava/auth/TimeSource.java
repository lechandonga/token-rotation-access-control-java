package com.github.lechandonga.tokenrotationaccesscontroljava.auth;

/**
 * 可替换的时间来源，测试中可手动推进时间，避免用例依赖真实等待。
 */
public interface TimeSource {

    long epochMillis();
}
