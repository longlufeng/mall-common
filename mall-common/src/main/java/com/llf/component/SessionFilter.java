package com.llf.component;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import com.alibaba.fastjson.JSONObject;
import com.llf.enums.ErrorCode;
import com.llf.utils.Result;

import io.netty.util.internal.StringUtil;
import lombok.extern.slf4j.Slf4j;

/**
 * 会话过滤器，校验会话是否超时
 * @author longlufeng
 *
 */
@Component
@Slf4j
@Order(2)
public class SessionFilter implements Filter{
	
	@Autowired
	private RedisTemplate<String, Object> redisTemplate;
	
	@Value("${sess.time-out:}")
	public String sessTimeOut;
	
	@Value("${url.no-need-chk-session:}")
	public String sessNoChk;

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
        
        // 4.不需要校验会话的uri放行以及微服务之间的内部调佣
		if(sessNoChk.indexOf(uri) > -1 || uri.indexOf("api") > -1) {
			chain.doFilter(servletRequest, servletResponse);
			return;
		}
		
		// 5.获取当前会话信息
		HttpSession session = req.getSession();
		String sessionId = session.getId();
		
		// 6.获取保存在redis的sessionId
		String redisSessionId = (String) redisTemplate.opsForValue().get("userId:"+session.getAttribute("userId"));
		
		// 7.判断会话超时
		if(StringUtil.isNullOrEmpty(sessionId)  || StringUtil.isNullOrEmpty(redisSessionId)) {
			Result<?> result = Result.failure(ErrorCode.USER_SESS_OUT.getCode(),ErrorCode.USER_SESS_OUT.getMsg());
            String resultStr = JSONObject.toJSONString(result);
            //指定编码，否则在浏览器中会中文乱码
            resp.setHeader("Content-Type", "application/json;charset=UTF-8");
            //将该字符串响应给前端
            resp.getWriter().write(resultStr);
            return;
		}
		
		// 8.判断当前用户是否在其他地方登录
		if(!sessionId.equals(redisSessionId)) {
			Result<?> result = Result.failure(ErrorCode.USER_EXCH_DEV.getCode(),ErrorCode.USER_EXCH_DEV.getMsg());
            String resultStr = JSONObject.toJSONString(result);
            resp.setHeader("Content-Type", "application/json;charset=UTF-8");
            resp.getWriter().write(resultStr);
            return;
		}
		
		// 9.更新会话过期时间
		redisTemplate.opsForValue().set("userId:"+session.getAttribute("userId"), sessionId,Long.parseLong(sessTimeOut),TimeUnit.SECONDS);
		
		chain.doFilter(servletRequest, servletResponse);
		
	}

}
