package com.llf.utils;

import java.io.Serializable;

import lombok.Data;

@Data
public class Result<T> implements Serializable {
 
    private static final long serialVersionUID = -3948389268046368059L;
 
    private String code = "200";
 
    private String msg = "交易成功";
 
    private T data;
    

    public Result() {
    }
    
    public Result(T data) {
        this.data = data;
    }
 
    public Result(String code, String msg) {
        this.code = code;
        this.msg = msg;
    }
    
    public Result(String code, String msg, T data) {
        this.code = code;
        this.msg = msg;
        this.data = data;
    }
    
	public static <T> Result<T> success() {
        return new Result<T>();
    }
 
	public static <T> Result<T> success(T data) {
        Result<T> result = new Result<T>();
        result.setData(data);
        return result;
    }
    
    public static <T> Result<T> failure() {
    	Result<T> result = new Result<T>();
        result.setCode("999999");
        result.setMsg("交易失败");
        return result;
    }
    
    public static <T> Result<T> failure(String msg) {
		Result<T> result = new Result<T>();
		 result.setMsg(msg);
        return result;
    }
 
	public static <T> Result<T> failure(String code,String msg) {
		Result<T> result = new Result<T>();
        result.setCode(code);
        result.setMsg(msg);
        return result;
    }
 
    public static <T> Result<T> failure(String code,String msg, T data) {
    	Result<T> result = new Result<T>();
        result.setCode(code);
        result.setMsg(msg);
        result.setData(data);
        return result;
    }
 
}