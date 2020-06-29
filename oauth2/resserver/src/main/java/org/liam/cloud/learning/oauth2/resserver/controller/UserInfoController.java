package org.liam.cloud.learning.oauth2.resserver.controller;

import java.util.HashMap;
import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user")
public class UserInfoController {

	@GetMapping("/info")
	public Map<String,Object> info() {
		Map<String,Object> map = new HashMap<String,Object>();
		//这个地方的wondersGroup必须要和client中配置的userNameAttribute相同才不会报错
		map.put("wondersGroup","{\"username\":\"吴爽\",\"workningNo\":\"CQ230\",\"baseLocation\":\"重庆\"}");
		return map;
	}
}
