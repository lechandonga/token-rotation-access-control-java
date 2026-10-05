package com.github.lechandonga.tokenrotationaccesscontroljava.config;

import com.github.lechandonga.tokenrotationaccesscontroljava.auth.TimeSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * 时间源配置独立成类，避免与 WebMvc 配置形成 Bean 构造期循环依赖。
 */
@Configuration
public class TimeConfiguration {

    @Bean
    public TimeSource systemTimeSource() {
        return System::currentTimeMillis;
    }
}
