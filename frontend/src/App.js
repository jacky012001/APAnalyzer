import './App.css';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import ProtectedRoute from './Components/ProtectedRoute';
import LoginForm from './Components/LoginForm/LoginForm';
import ForgotPasswordForm from './Components/ForgotPasswordForm/ForgotPasswordForm';
import SetNewPasswordForm from './Components/SetNewPasswordForm/SetNewPasswordForm';
import NotFound from './Components/NotFound/NotFound';
import Dashboard from './Components/Dashboard/Dashboard';
import RealTimeTrafficMonitoring from './Components/RealTimeTrafficMonitoring/RealTimeTrafficMonitoring';
import MLModelTraining from './Components/MLModelTraining/MLModelTraining';
import ThreatDetectionReport from './Components/ThreatDetectionReport/ThreatDetectionReport';
import ChatbotAssistance from './Components/ChatbotAssistance/ChatbotAssistance';

function App() {
  return (
    <Router>
      <Routes>
        <Route path='/' element={<LoginForm />}/>
        <Route path='/login' element={<LoginForm />}/>
        <Route path='/forgot-password' element={<ForgotPasswordForm />}/>
        <Route path='/reset-password/:token' element={<SetNewPasswordForm />} />
        <Route path='*' element={<NotFound />}/>

        {/* Protect the dashboard route */}
        <Route path='/dashboard' element={<ProtectedRoute element={Dashboard} />} />
        <Route path='/real-time-traffic-monitoring' element={<ProtectedRoute element={RealTimeTrafficMonitoring}/>}/>
        <Route path='/threat-detection-report' element={<ProtectedRoute element={ThreatDetectionReport}/>}/>
        <Route path='/ml-model-training' element={<ProtectedRoute element={MLModelTraining}/>}/>
        <Route path='/chatbot' element={<ProtectedRoute element={ChatbotAssistance}/>}/>
        {/*******************************/}
    </Routes>
    </Router>
  );
}

export default App;
