import React, { useState, useEffect } from 'react';
import './LoginForm.css';
import { FaUser, FaLock } from "react-icons/fa";

const LoginForm = () => {
  const [showPassword, setShowPassword] = useState(false);
  const [currentDateTime, setCurrentDateTime] = useState(new Date());

  const handleShowPassword = () => {
    setShowPassword(!showPassword);
  }

  useEffect(() => {
    const timer = setInterval(() => {
        setCurrentDateTime(new Date());
    }, 1000);
    return () => clearInterval(timer);
  }, []);
    
  return (
    <div className='wrapper'>
        <div className="datetime">
            {currentDateTime.toLocaleString()}
        </div>

        <img src="./logo.png" alt="APAnalyzer Logo" className="logo" />

        <form action="">
            <h1>Login</h1>
            <div className="input-box">
                <input type="text" placeholder='Username' required />
                <FaUser className='icon' />
            </div>
            <div className="input-box">
                <input type={showPassword ? 'text' : 'password'} placeholder='Password' required /> {/* showPassword state to conditionally set the type attribute of password input field to either 'text' or 'password' */}
                <FaLock className='icon'/>
            </div>

            <div className="remember-forgot">
                <label><input type="checkbox" onChange={handleShowPassword}/>Show password</label>
                <a href='#'>Forgot password?</a>
            </div>

            <button type="submit">Login</button>

            <div className="register-link">
                <p>Need a new account? <a href='#'>Register</a></p>
            </div>
        </form>
    </div>
  )
}

export default LoginForm;