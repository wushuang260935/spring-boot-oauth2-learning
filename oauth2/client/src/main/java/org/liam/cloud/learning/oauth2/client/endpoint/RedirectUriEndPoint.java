package org.liam.cloud.learning.oauth2.client.endpoint;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@RestController
@RequestMapping("/endpoint")
public class RedirectUriEndPoint {
	
	@Autowired
	OAuth2ClientProperties properties;
	
	
	/**
	 * 
	 * @param code 授权码 authorization code用于获取access_token
	 * @param state 状态码，上一个步骤中，我们发送给auth server的，现在需要对其进行验证
	 * @throws Exception 
	 */
	@GetMapping("/token")
	public void getAccessToken(String code,String state,HttpServletRequest request) throws Exception {
		if(state == null) {//这里的state在客户端里肯定是有规律的，需要自行验证
			return;
		}
		
		//验证成功了之后，就发送一个请求到auth server的token endpoint
		HttpHeaders header = new HttpHeaders();
		//请求需要application/x-www-form-urlencoded格式
		header.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		
		//装入请求参数
		MultiValueMap<String,String> map = new LinkedMultiValueMap<String, String>();
		map.set("grant_type", "authorization_code");
		map.set("code",code);
		map.set("redirect_uri", "http://localhost:81/endpoint/token");//client的重定向地址.也就是本地址http://localhost:81/endpoint/token
		map.set("client_id","client");//本client的clientid
		
		//创建entity
		HttpEntity<MultiValueMap<String,String>> entity = new HttpEntity<MultiValueMap<String,String>>(map,header);
		//创建RestTemplate
		RestTemplate template = new RestTemplate();
		ResponseEntity<OAuth2AccessToken> response = template.postForEntity(getTokenUri(), entity, OAuth2AccessToken.class);
		
		if(response.getStatusCode() != HttpStatus.OK) {
			throw new Exception("获取accessToken失败");
		}
		OAuth2AccessToken token = response.getBody();
		
		//下一步，使用token访问res server获取资源
		request.getSession().setAttribute("access_token", token); 
	}
	
	private String getTokenUri() {
		return properties.getProvider().get("oauth2-learning-provide").getTokenUri();
	}
}
