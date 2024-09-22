import React, { useState } from 'react';
import './ForgotPasswordForm.css';
import Swal from 'sweetalert2';
import { MdEmail } from "react-icons/md";
import { sendResetLinkEmail } from '../services/apiService';

const ForgotPasswordForm = () => {
    const [email, setEmail] = useState('');

    const handleSubmit = async (e) => {
        e.preventDefault();
        try{
            const response = await sendResetLinkEmail(email);
            console.log(response);
            Swal.fire({
                icon: "success",
                title: "Email sent!",
                text: response.message,
                timer: 3000,
            });
        } catch (error){
            Swal.fire({
                icon: "error",
                title: "Email not sent!",
                text: error.message,
                timer: 3000,
            });
        }
    };

    return (
        <div className='forgot-password-wrapper'>
            <h1>Forgot Password? Don't worry, we got your back!</h1>
            <p>Please enter your email address! You will receive a link to create a new password via email!</p>
            
            <img src="./logo.png" alt="APAnalyzer Logo" className="logo" />

            <form onSubmit={handleSubmit}>
                <div className='email-input-box'>
                    <input
                    type='email'
                    placeholder='Email Address'
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    title=''
                    required
                    />
                    <MdEmail className='icon' />
                </div>
                <button type='submit' className='submit-button'>Submit</button>
            </form>
        </div>
    )
};

export default ForgotPasswordForm;