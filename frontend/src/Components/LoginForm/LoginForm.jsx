import React, { useState, useEffect } from 'react';
import './LoginForm.css';
import { FaLock } from "react-icons/fa";
import { MdEmail } from "react-icons/md";
import { login } from '../services/apiService';
import Swal from 'sweetalert2';
import { Link, useNavigate } from 'react-router-dom';

const LoginForm = () => {
  const [showPassword, setShowPassword] = useState('');
  const [currentDateTime, setCurrentDateTime] = useState(new Date());
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const navigate = useNavigate();

  const handleShowPassword = () => {
    setShowPassword(!showPassword);
  }

  useEffect(() => {
    const timer = setInterval(() => {
        setCurrentDateTime(new Date());
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    try{
      const response = await login(email, password);
      console.log(response);
      Swal.fire({
        icon: "success",
        title: "Signed in successfully!",
        text: "Welcome to APAnalyzer, pals!",
        timer: 3000,
      });
      localStorage.setItem('token', response.token); /* Store the token */

      // Redirect to the NTA page after successfully login
      navigate('/dashboard');

    } catch (error){
      Swal.fire({
        icon: "error",
        title: "Signed in failed!",
        text: "Oops! Looks like you entered wrong email or password!",
        timer: 3000,
      });
    }
  };
    
  return (
    <div className='wrapper'>
        <div className="datetime">
            {currentDateTime.toLocaleString()}
        </div>

        <img src="./logo.png" alt="APAnalyzer Logo" className="logo" />

        <form onSubmit={handleSubmit}>
            <h1>Login</h1>
            <div className="input-box">
                <input 
                type="text" 
                placeholder='Email'
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                title=''
                required
                />
                <MdEmail className='icon' />
            </div>
            <div className="input-box">
                <input 
                type={showPassword ? 'text' : 'password'} 
                placeholder='Password' 
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                title=''
                required 
                />
                <FaLock className='icon'/>
            </div>

            <div className="remember-forgot">
                <label>
                  <input type="checkbox" onChange={handleShowPassword}/>Show password
                </label>
                <Link to='/forgot-password'>Forgot password?</Link>
            </div>

            <button type="submit">Login</button>

        </form>
    </div>
  )
}

export default LoginForm;