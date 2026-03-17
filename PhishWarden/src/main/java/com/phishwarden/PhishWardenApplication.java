package com.phishwarden;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class PhishWardenApplication {
    public static void main(String[] args) {
        SpringApplication.run(PhishWardenApplication.class, args);
    }
}