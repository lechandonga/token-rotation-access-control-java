package com.github.lechandonga.tokenrotationaccesscontroljava.tests.support;

import com.github.lechandonga.tokenrotationaccesscontroljava.auth.TimeSource;

import java.util.concurrent.atomic.AtomicLong;

/**
 * 可控时间源：测试中手动推进时间，过期/宽限用例无需真实等待。
 */
public class ControllableTimeSource implements TimeSource {

    private final AtomicLong now = new AtomicLong(System.currentTimeMillis());

    @Override
    public long epochMillis() {
        return now.get();
    }

    public void advanceMillis(long deltaMillis) {
        now.addAndGet(deltaMillis);
    }

    /** 将虚拟时间重置为真实当前时间，保证用例之间互不干扰。 */
    public void reset() {
        now.set(System.currentTimeMillis());
    }

    public void advanceSeconds(long seconds) {
        advanceMillis(seconds * 1000L);
    }

    public void advanceMinutes(long minutes) {
        advanceSeconds(minutes * 60L);
    }

    public void advanceHours(long hours) {
        advanceMinutes(hours * 60L);
    }

    public void advanceDays(long days) {
        advanceHours(days * 24L);
    }
}
