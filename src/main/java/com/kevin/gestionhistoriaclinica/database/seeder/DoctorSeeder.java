package com.kevin.gestionhistoriaclinica.database.seeder;

import com.github.javafaker.Faker;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.util.stream.IntStream;

import com.kevin.gestionhistoriaclinica.models.dto.user.DoctorStoreDto;
import com.kevin.gestionhistoriaclinica.models.dto.user.UserDto;
import com.kevin.gestionhistoriaclinica.services.user.IDoctorService;

@Component
public class DoctorSeeder implements Runnable {

    @Autowired
    private IDoctorService doctorService;

    @Override
    public void run() {
        Faker faker = new Faker();

        IntStream.range(0, 10).forEach(i -> {
            DoctorStoreDto doctorDto = DoctorStoreDto.builder()
                    .code(faker.idNumber().valid())
                    .user(UserDto.builder()
                            .fullName(faker.name().fullName())
                            .email(faker.internet().emailAddress())
                            .password(faker.internet().password())
                            .enabled(true)
                            .build())
                    .build();

            doctorService.save(doctorDto);
        });

        System.out.println("Doctor seeder executed");
    }
}
