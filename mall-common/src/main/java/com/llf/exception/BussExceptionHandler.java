package com.llf.exception;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import com.llf.utils.Result;

@Order(3)
@RestControllerAdvice
public class BussExceptionHandler {

    private final static Logger logger = LoggerFactory.getLogger(BussExceptionHandler.class);

    /**
              * 自定义异常处理
     *
     * @param e
     * @return
     */
    @ExceptionHandler(BussException.class)
    public Result<?> handleBussException(BussException e) {
        logger.info(e.getMessage());
        e.printStackTrace();
        return Result.failure(e.getCode(), e.getMessage());
    }

    /**
     * exception异常处理
     *
     * @param e
     * @return
     */
    @ExceptionHandler(Exception.class)
    public Result<?> handleException(Exception e) {
        logger.info(e.getMessage());
        e.printStackTrace();
        return Result.failure("接口异常，错误信息为" + e.getMessage());
    }

    /**
              * 权限异常
     *
     * @param e
     * @return
     */
//    @ExceptionHandler({UnauthorizedException.class, AuthorizationException.class})
//    public Result<?> handleAuthorizationException(AuthorizationException e) {
//        logger.info(e.getMessage());
//        e.printStackTrace();
//        return Result.error(CommonEnum.SC_NO_JURISDICTION.getCode(), CommonEnum.SC_NO_JURISDICTION.getMessage());
//    }
}
