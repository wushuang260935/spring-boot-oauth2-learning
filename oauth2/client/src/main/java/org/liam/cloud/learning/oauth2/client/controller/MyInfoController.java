package org.liam.cloud.learning.oauth2.client.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MyInfoController {

	@GetMapping("/getmyinfo")
	public String getMyInfo() {
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		return auth.toString();
	}
}
