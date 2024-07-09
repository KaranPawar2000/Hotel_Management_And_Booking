package com.hotel_management.karan.service.interfac;

import com.hotel_management.karan.dto.Response;
import com.hotel_management.karan.entity.Booking;

public interface IBookingService {

    Response saveBooking(Long roomId, Long userId, Booking bookingRequest);
    Response findBookingByConfirmationCode(String confirmationCode);
    Response getAllBookings();
    Response cancelBooking(Long bookingId);

}
