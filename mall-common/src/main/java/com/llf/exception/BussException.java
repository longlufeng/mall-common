package com.llf.exception;

public class BussException extends Exception{

	/**
	 * 系列版本号
	 */
	private static final long serialVersionUID = 2L;

	/**
	 * 错误码
	*/
	private String code;

    /**
           * 错误信息
    */
	private String message;

	public String getCode() {
		return code;
	}
	
	public void setCode(String code) {
		this.code = code;
	}
	
	public String getMessage() {
		return message;
	}
	
	public void setMessage(String message) {
		this.message = message;
	}

	public BussException(String code, String message) {
		super();
		this.code = code;
		this.message = message;
	}
	
}
