package com.dp.resource.controller;


import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api")
public class UserController {

    /**
     * 公开接口 - 不需要 Token
     */
    @GetMapping("/public/health")
    public Map<String, Object> health() {
        Map<String, Object> result = new HashMap<>();
        result.put("status", "UP");
        result.put("service", "resource-server");
        result.put("message", "Service is running");
        return result;
    }

    /**
     * 用户信息接口 - 需要 Token
     * 通过 Principal 获取当前登录用户
     */
    @GetMapping("/user/info")
    public Map<String, Object> getUserInfo(Principal principal) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        log.info("Username : {}", authentication.getName());
        Map<String, Object> result = new HashMap<>();
        result.put("username", principal.getName());
        result.put("authenticated", authentication.isAuthenticated());
        result.put("authorities", authentication.getAuthorities());
        result.put("service", "resource-server");

        return result;
    }

    /**
     * 管理员接口 - 需要 ADMIN 角色
     */
    @GetMapping("/admin/dashboard")
    public Map<String, Object> adminDashboard() {
        Map<String, Object> result = new HashMap<>();
        result.put("data", "Admin Dashboard Data");
        result.put("service", "resource-server");
        return result;
    }
}