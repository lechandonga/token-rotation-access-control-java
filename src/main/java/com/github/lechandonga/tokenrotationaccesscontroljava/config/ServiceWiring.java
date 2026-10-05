package com.github.lechandonga.tokenrotationaccesscontroljava.config;

import com.github.lechandonga.tokenrotationaccesscontroljava.auth.TokenService;
import com.github.lechandonga.tokenrotationaccesscontroljava.token.KeyManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ServiceWiring {

    @Bean
    TokenService.KeyManagerLookup keyManagerLookup(KeyManager keyManager) {
        return () -> keyManager;
    }
}
