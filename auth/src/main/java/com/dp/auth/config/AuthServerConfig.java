package com.dp.auth.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

/**
 * 认证服务器配置
 * ============================================
 * 认证方式：OAuth2 密码模式（Password Grant）
 *
 * 流程说明：
 * 1. 客户端使用用户名/密码向 /oauth/token 请求 token
 * 2. 认证服务器验证用户名密码，生成 JWT Token 返回
 * 3. 客户端携带 Token 访问资源服务器
 * ============================================
 */
@Configuration
@EnableWebSecurity
@EnableAuthorizationServer  // 启用 OAuth2 认证服务器
public class AuthServerConfig {

    /**
     * 密码编码器
     * 使用 BCrypt 加密，存储时自动加盐
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 用户认证管理器
     * 负责验证用户名和密码
     */
    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        return http.getSharedObject(AuthenticationManagerBuilder.class)
                .userDetailsService(userDetailsService())
                .passwordEncoder(passwordEncoder())
                .and()
                .build();
    }

    /**
     * 用户详情服务
     * 定义测试用户：admin/123456
     * 密码使用 BCrypt 加密
     */
    @Bean
    public UserDetailsService userDetailsService() {
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        // 密码: 123456 的 BCrypt 加密结果
        manager.createUser(User.withUsername("admin")
                .password("$2a$10$N.zmdr9k7uOCQb376NoUnuTJ8iAt6Z5EHsM8lE9lBOsl7iKTVKIUi")
                .roles("USER", "ADMIN")
                .build());
        manager.createUser(User.withUsername("user")
                .password("$2a$10$N.zmdr9k7uOCQb376NoUnuTJ8iAt6Z5EHsM8lE9lBOsl7iKTVKIUi")
                .roles("USER")
                .build());
        return manager;
    }

    /**
     * JWT Token 存储
     * 使用 JWT 格式存储 Token，无需 Redis
     */
    @Bean
    public TokenStore tokenStore() {
        return new JwtTokenStore(jwtAccessTokenConverter());
    }

    /**
     * JWT Token 转换器
     * 配置签名密钥，用于生成和验证 JWT
     */
    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        // 签名密钥（生产环境请使用更强的密钥）
        converter.setSigningKey("sso-secret-key-2024");
        return converter;
    }

    /**
     * Spring Security 配置
     * 允许所有用户访问 /oauth/token 端点
     */
    @Configuration
    public static class SecurityConfig extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .authorizeRequests()
                    .antMatchers("/oauth/token", "/oauth/authorize").permitAll()
                    .anyRequest().authenticated()
                    .and()
                    .csrf().disable()
                    .formLogin().disable()
                    .httpBasic();
        }
    }

    /**
     * OAuth2 授权服务器配置
     * 定义客户端信息和 Token 端点
     */
    @Configuration
    public static class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

        private final AuthenticationManager authenticationManager;
        private final TokenStore tokenStore;
        private final JwtAccessTokenConverter jwtAccessTokenConverter;

        public AuthorizationServerConfig(
                AuthenticationManager authenticationManager,
                TokenStore tokenStore,
                JwtAccessTokenConverter jwtAccessTokenConverter) {
            this.authenticationManager = authenticationManager;
            this.tokenStore = tokenStore;
            this.jwtAccessTokenConverter = jwtAccessTokenConverter;
        }

        /**
         * 配置客户端信息
         * 定义哪些应用可以访问认证服务器
         */
        @Override
        public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
            // 使用 BCrypt 编码客户端密码
            PasswordEncoder encoder = new BCryptPasswordEncoder();
            String encodedClientSecret = encoder.encode("gateway-secret");

            clients.inMemory()
                    .withClient("gateway-client")
                    .secret(encodedClientSecret)  // 使用 BCrypt 编码的密码
                    .authorizedGrantTypes(
                            "password",
                            "refresh_token"
                    )
                    .scopes("all", "read", "write")
                    .accessTokenValiditySeconds(3600)
                    .refreshTokenValiditySeconds(86400);
        }
        /**
         * 配置 Token 端点
         * 设置认证管理器和 Token 存储
         */
        @Override
        public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
            endpoints
                    .authenticationManager(authenticationManager)  // 密码模式需要
                    .tokenStore(tokenStore)                         // Token 存储
                    .accessTokenConverter(jwtAccessTokenConverter); // JWT 转换器
        }

        /**
         * 配置 Token 端点的安全策略
         * 允许表单认证和客户端认证
         */
        @Override
        public void configure(AuthorizationServerSecurityConfigurer security) {
            security
                    .tokenKeyAccess("permitAll()")           // 允许所有访问 /oauth/token_key
                    .checkTokenAccess("isAuthenticated()")   // 检查 Token 需要认证
                    .allowFormAuthenticationForClients();    // 允许表单认证
        }
    }
}