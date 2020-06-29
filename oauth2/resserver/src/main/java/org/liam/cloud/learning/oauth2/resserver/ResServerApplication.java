package org.liam.cloud.learning.oauth2.resserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;

/**
 * Hello world!
 *
 */
@EnableResourceServer
@SpringBootApplication
public class ResServerApplication 
{
    public static void main( String[] args )
    {
    	SpringApplication.run(ResServerApplication.class, args);
    }
}
