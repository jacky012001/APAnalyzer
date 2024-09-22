import React from 'react';
import { Navigate } from 'react-router-dom';

const ProtectedRoute = ({ element: Component }) => {
  const token = localStorage.getItem('token');  // Check for token in localStorage

  return token ? <Component /> : <Navigate to="/login" />;  // Redirect to login if no token
};

export default ProtectedRoute;