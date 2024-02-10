package org.techlab.labxpert;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.techlab.labxpert.Enum.RoleUser;
import org.techlab.labxpert.Enum.StatutEchantillon;
import org.techlab.labxpert.Enum.StatutNumeration;
import org.techlab.labxpert.config.RsakeysConfig;
import org.techlab.labxpert.entity.*;
import org.techlab.labxpert.repository.*;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

import java.text.SimpleDateFormat;
import java.util.Date;

@SpringBootApplication
@EnableScheduling
@EnableSwagger2
@EnableConfigurationProperties(RsakeysConfig.class)
public class LabXpertApplication{

	public static void main(String[] args) {
		SpringApplication.run(LabXpertApplication.class, args);
	}

	@Bean
	public PasswordEncoder passwordEncoder(){
		return new BCryptPasswordEncoder();
	}
}
