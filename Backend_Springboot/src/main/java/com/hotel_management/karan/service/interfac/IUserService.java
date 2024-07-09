package com.hotel_management.karan.service.interfac;
import com.hotel_management.karan.dto.LoginRequest;
import com.hotel_management.karan.dto.Response;
import com.hotel_management.karan.entity.User;

public interface IUserService {
    Response register(User user);

    Response login(LoginRequest loginRequest);

    Response getAllUsers();

    Response getUserBookingHistory(String userId);

    Response deleteUser(String userId);

    Response getUserById(String userId);

    Response getMyInfo(String email);

}
