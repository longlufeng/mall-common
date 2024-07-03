package com.llf.component;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import com.alibaba.fastjson.JSONObject;
import com.llf.enums.ErrorCode;
import com.llf.utils.Result;

import io.netty.util.internal.StringUtil;
import lombok.extern.slf4j.Slf4j;

/**
 * 登录权限认证，判断用户是否已经登录
 * @author longlufeng
 *
 */
@Component
@Slf4j
@Order(0)
public class LoginAuthFilter implements Filter{
	
	@Value("${url.no-need-chk-login:}")
	public String noNeedChkLoginUrls;

	@Override
	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain)
			throws IOException, ServletException {
		
		// 1.将Servlet转化为HttpServlet
		HttpServletRequest req = (HttpServletRequest) servletRequest;
		HttpServletResponse resp = (HttpServletResponse) servletResponse;
		
		// 2.获取请求url
		String url = req.getRequestURL().toString();
		log.info("\n url:{}",url);
		
		// 3.获取请求uri
        String uri = req.getRequestURI().toString();
        log.info("\n uri:{}",uri);
        
        // 4.不需要校验会话的uri放行
		if(noNeedChkLoginUrls.indexOf(uri) > -1 || uri.indexOf("api") > -1) {
			chain.doFilter(servletRequest, servletResponse);
			return;
		}
		
		// 5.获取请求头token
		String token = req.getHeader("token");
		
		// 6.判断token是否存在，存在，已登录，否则，未登录
		if(StringUtil.isNullOrEmpty(token)) {
			Result<?> result = Result.failure(ErrorCode.USER_NO_LOGIN.getCode(),ErrorCode.USER_NO_LOGIN.getMsg());
            String resultStr = JSONObject.toJSONString(result);
            //指定编码，否则在浏览器中会中文乱码
            resp.setHeader("Content-Type", "application/json;charset=UTF-8");
            //将该字符串响应给前端
            resp.getWriter().write(resultStr);
            return;
		}
		
		chain.doFilter(servletRequest, servletResponse);
		
	}

}
