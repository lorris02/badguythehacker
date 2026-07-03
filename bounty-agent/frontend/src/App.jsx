import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import Login    from "./pages/Login";
import Register from "./pages/Register";
import Home     from "./pages/Home";

function PrivateRoute({ children }) {
  return localStorage.getItem("ba_token") ? children : <Navigate to="/login" replace />;
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login"    element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="/" element={<PrivateRoute><Home /></PrivateRoute>} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
