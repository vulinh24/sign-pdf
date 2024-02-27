package com.pdfsignature.utils;

public class SignaturesException extends Exception{

	private static final long serialVersionUID = -3903529918407257410L;
	
	public SignaturesException(String message){
		super(message);
	}
	
	public SignaturesException(String message, Throwable e){
		super(message, e);
	}
}
