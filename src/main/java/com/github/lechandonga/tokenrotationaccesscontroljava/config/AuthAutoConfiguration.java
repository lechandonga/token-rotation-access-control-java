package com.github.lechandonga.tokenrotationaccesscontroljava.config;

import com.github.lechandonga.tokenrotationaccesscontroljava.web.AuthenticatedPrincipalArgumentResolver;
import com.github.lechandonga.tokenrotationaccesscontroljava.web.BearerAuthInterceptor;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.List;

@Configuration
@EnableConfigurationProperties(AuthProperties.class)
public class AuthAutoConfiguration implements WebMvcConfigurer {

    private final BearerAuthInterceptor bearerAuthInterceptor;
    private final AuthenticatedPrincipalArgumentResolver principalArgumentResolver;

    public AuthAutoConfiguration(BearerAuthInterceptor bearerAuthInterceptor,
                                 AuthenticatedPrincipalArgumentResolver principalArgumentResolver) {
        this.bearerAuthInterceptor = bearerAuthInterceptor;
        this.principalArgumentResolver = principalArgumentResolver;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(bearerAuthInterceptor).addPathPatterns("/api/**");
    }

    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
        resolvers.add(principalArgumentResolver);
    }
}
