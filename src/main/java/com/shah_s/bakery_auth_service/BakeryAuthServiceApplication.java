package com.shah_s.bakery_auth_service;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
@EnableDiscoveryClient
public class BakeryAuthServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(BakeryAuthServiceApplication.class, args);
	}

}
