package com.pluralsight.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
public class LoginController {
	
	@RequestMapping(value="/login", method=RequestMethod.GET)
	public String login(ModelMap model){
		System.out.println("In the login Method");
		return "login";
	}
	
	@RequestMapping(value="/loginFailed", method=RequestMethod.GET)
	public String loginFailed(ModelMap model){
		System.out.println("Login Failed");
		model.addAttribute("error", "true");
		return "login";
	}
	
	@RequestMapping(value="logout")
	public String logout(ModelMap model){
		System.out.println("In logout method");
		return "logout";
	}
	
	@RequestMapping(value="403")
	public String error403(ModelMap model){
		return "403";
	}
}
