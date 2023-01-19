package com.example.eindopdrachtbackendv1.DTOS.Input;

import lombok.Data;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;
import java.time.LocalDate;

@Data
public class UserInputDto {

    private Long id;

    private String username;

    @NotBlank
    @Size(min = 6)
    private String password;

    @Email
    private String email;

    private LocalDate dob;
}
