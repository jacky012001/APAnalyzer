import React, { useState } from 'react';
import './SetNewPasswordForm.css';
import Swal from 'sweetalert2';
import { useParams } from 'react-router-dom';
import { FaUserLock } from "react-icons/fa";
import { setNewPassword } from '../services/apiService';

const SetNewPasswordForm = () => {
    const { token } = useParams();
    const [password, setPassword] = useState('');
    const [passwordConfirmation, setPasswordConfirmation] = useState('');
    const email = new URLSearchParams(window.location.search).get('email');

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (password !== passwordConfirmation) {
            Swal.fire({
                icon: "error",
                title: "Error!",
                text: "Passwords do not match!",
                timer: 2000,
                timerProgressBar: true,
                showConfirmButton: false,
            });
            return;
        }
        try {
            const response = await setNewPassword({ email, password, password_confirmation: passwordConfirmation, token });
            console.log(response);
            Swal.fire({
                icon: "success",
                title: "New password set successfully! You will be redirected to login page in 10 seconds!",
                text: response.message,
                timer: 10000,
                timerProgressBar: true,
                showConfirmButton: false,
            }).then(() => {
                window.location.href = 'http://localhost:3000/login';
            });
        } catch (error) {
            Swal.fire({
                icon: "error",
                title: "New password set failed!",
                text: error.message,
                timer: 3000,
            });
        }
    };

    return (
        <div className='set-new-password-wrapper'>
            <img src="/logo.png" alt="APAnalyzer Logo" className="logo" />

            <h1>Time to change your old password!</h1>

            <form onSubmit={handleSubmit}>
                <div className='new-password-input-box'>
                    <input
                    type='password'
                    placeholder='New Password'
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    title=''
                    required
                    />
                    <FaUserLock className='icon'/>
                </div>

                <div className='new-password-input-box-confirmation'>
                    <input 
                    type='password'
                    placeholder='Confirm New Password'
                    value={passwordConfirmation}
                    onChange={(e) => setPasswordConfirmation(e.target.value)}
                    title=''
                    required
                    />
                    <FaUserLock className='icon'/>
                    <button type='submit' className='submit-button'>Reset Password</button>
                </div>
            </form>
        </div>
    );
};

export default SetNewPasswordForm;