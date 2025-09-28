package com.shah_s.bakery_auth_service;

import org.springframework.boot.SpringApplication;

public class TestBakeryAuthServiceApplication {

	public static void main(String[] args) {
		SpringApplication.from(BakeryAuthServiceApplication::main).with(TestcontainersConfiguration.class).run(args);
	}

}
