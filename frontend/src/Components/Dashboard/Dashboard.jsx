import React from 'react';
import { useNavigate } from 'react-router-dom';
import Swal from 'sweetalert2';
import './Dashboard.css';

const Dashboard = () => {
  const navigate = useNavigate();

  const handleLogout = () => {
    localStorage.removeItem('token');
    navigate('/');
  }

  const showMLEntranceAlert = () => {
    Swal.fire({
      icon: 'info',
      title: 'Proceed to Machine Learning Section...',
      text: 'Notice! This section is for those who want to execute Machine Learning and understand how to run it!',
      showCancelButton: true,
      confirmButtonText: 'Proceed',
      cancelButtonText: 'Cancel',
    }).then((result) => {
      if(result.isConfirmed){
        navigate('/ml-model-training');
      }
    })
  };

  return (
    <div className="dashboard-container">
      <h1>Dashboard</h1>
      <div className="buttons-grid">
        {/* Real Time Traffic Monitoring */}
        <button className="dashboard-button" onClick={() => navigate('/real-time-traffic-monitoring')}>
          Real Time Traffic Monitoring
        </button>

        {/* Threat Detection Report */}
        <button className="dashboard-button" onClick={() => navigate('/threat-detection-report')}>
          Threat Detection & Solution Report
        </button>

        {/* ML Model Training (Placeholder) */}
        <button className="dashboard-button" onClick={showMLEntranceAlert}>
          ML Model Training
        </button>

        {/* Chatbot Assistance (Placeholder) */}
        <button className="dashboard-button" onClick={() => navigate('/chatbot')}>
          Chatbot Assistance
        </button>

        {/* Logout */}
        <button className="dashboard-button logout-button" onClick={handleLogout}>
          Logout
        </button>
      </div>
    </div>
  );
};

export default Dashboard;