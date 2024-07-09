
import  React from "react"
import { BrowserRouter,Routes,Route,Navigate } from 'react-router-dom';
import Navbar from './component/common/NavBar';
import FooterComponent from './component/common/Footer';
import HomePage from './component/home/HomePage';
import AllRoomsPage from "./component/booking_rooms/AllRoomsPage";
import FindBookingPage from "./component/booking_rooms/FindBookingPage";
import RoomDetailsPage from "./component/booking_rooms/RoomDetailsPage";
import LoginPage from "./component/auth/LoginPage";
import RegisterPage from "./component/auth/RegisterPage";
import ProfilePage from "./component/profile/ProfilePage";
import EditProfilePage from "./component/profile/EditProfilePage";
import { ProtectedRoute,AdminRoute } from "./service/guard";
import AdminPage from "./component/admin/AdminPage";
import AddRoomPage from "./component/admin/AddRoomPage";
import EditBookingPage from "./component/admin/EditBookingPage";
import EditRoomPage from "./component/admin/EditRoomPage";
import ManageBookingsPage from "./component/admin/ManageBookingsPage";
import ManageRoomPage from "./component/admin/ManageRoomPage";
function App() {
  return (
    <BrowserRouter>
    <div className="App">
      <Navbar/>
      <div className='content'>
        <Routes>
          {/*Public routes*/}
        <Route exact path='/home'  element={<HomePage/>}/>
        <Route exact path='/rooms'  element={<AllRoomsPage/>}/>
        <Route exact path='/find-booking'  element={<FindBookingPage/>}/>
        <Route exact path='/login'  element={<LoginPage/>}/>
        <Route exact path='/register'  element={<RegisterPage/>}/>

          {/* authenticated users routes */}
        <Route exact path='/room-details-book/:roomId'  element={<ProtectedRoute element={<RoomDetailsPage/>}/>} />
        <Route exact path='/profile'  element={<ProtectedRoute element={<ProfilePage/>}/>} />
        <Route exact path='/edit-profile'  element={<ProtectedRoute element={<EditProfilePage/>}/>} />

           {/* Admin Routes */}
           <Route path="/admin"
              element={<AdminRoute element={<AdminPage />} />}
            />
            <Route path="/admin/manage-rooms"
              element={<AdminRoute element={<ManageRoomPage />} />}
            />
            <Route path="/admin/edit-room/:roomId"
              element={<AdminRoute element={<EditRoomPage />} />}
            />
            <Route path="/admin/add-room"
              element={<AdminRoute element={<AddRoomPage />} />}
            />
            <Route path="/admin/manage-bookings"
              element={<AdminRoute element={<ManageBookingsPage />} />}
            />
            <Route path="/admin/edit-booking/:bookingCode"
              element={<AdminRoute element={<EditBookingPage />} />}
            />

            {/* Fallback Route */}
            <Route path="*" element={<Navigate to="/login" />} />
          </Routes>


  
      </div>
      <FooterComponent/>
    </div>
    </BrowserRouter>
  );
}

export default App;
