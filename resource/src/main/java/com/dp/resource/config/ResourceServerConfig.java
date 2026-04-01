package com.dp.resource.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

/**
 * 资源服务器配置
 * ============================================
 * 验证流程：
 * 1. 使用与认证服务器相同的 JWT 签名密钥
 * 2. 验证 Token 签名和有效期
 *
 * 关键：setSigningKey() 用于设置签名密钥（验证时使用）
 * ============================================
 */
@Configuration
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {

    /**
     * JWT 签名密钥（必须与认证服务器完全一致）
     */
    private static final String JWT_SIGNING_KEY = "sso-secret-key-2024";

    /**
     * Token 存储 - 使用 JWT 格式
     */
    @Bean
    public TokenStore tokenStore() {
        return new JwtTokenStore(jwtAccessTokenConverter());
    }

    /**
     * JWT Token 转换器 - 配置签名密钥
     *
     * 注意：使用 setSigningKey() 而不是 setVerificationKey()
     * 在 Spring Security OAuth2 中，JwtAccessTokenConverter 使用 setSigningKey() 同时处理签名和验证
     */
    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        // 设置签名密钥（必须与认证服务器相同）
        converter.setSigningKey(JWT_SIGNING_KEY);
        return converter;
    }

    /**
     * Token 服务
     */
    @Bean
    public DefaultTokenServices tokenServices() {
        DefaultTokenServices services = new DefaultTokenServices();
        services.setTokenStore(tokenStore());
        return services;
    }

    /**
     * 配置资源ID
     */
    @Override
    public void configure(ResourceServerSecurityConfigurer resources) {
        resources.resourceId("resource-server")
                .stateless(true)
                .tokenServices(tokenServices());
    }

    /**
     * 配置接口访问权限
     */
    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                // 公开接口
                .antMatchers("/api/public/**").permitAll()
                // 用户接口需要认证
                .antMatchers("/api/user/**").authenticated()
                // 管理员接口需要 ADMIN 角色
                .antMatchers("/api/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
                .and()
                .csrf().disable();
    }
}