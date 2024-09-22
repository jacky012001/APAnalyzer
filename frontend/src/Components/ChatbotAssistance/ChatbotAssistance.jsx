import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './ChatbotAssistance.css';
import { useNavigate } from 'react-router-dom';

const ChatbotAssistance = () => {
    const [message, setMessage] = useState('');
    const [response, setResponse] = useState(''); 
    const [file, setFile] = useState(null);
    const [isLoading, setIsLoading] = useState(false);
    const [isFileUploaded, setIsFileUploaded] = useState(false);
    const [currentDateTime, setCurrentDateTime] = useState(new Date());
    const navigate = useNavigate();

    useEffect(() => {
        const timer = setInterval(() => {
            setCurrentDateTime(new Date());
        }, 1000);

        return () => {
            clearInterval(timer);
        };
    }, []);

    const handleLogout = () => {
        localStorage.removeItem('token');
        navigate('/');
    };

    const handleBackToDashboard = () => {
        navigate('/dashboard');
    };

    // Handle file upload
    const handleFileChange = (event) => {
        setFile(event.target.files[0]);
    };

    // Function to handle dataset upload
    const handleFileUpload = async(event) => {
        event.preventDefault();
        if (!file) {
            setResponse('Please upload a dataset first.');
            return;
        }

        setIsLoading(true);

        const formData = new FormData();
        formData.append('file', file);

        try {
            const res = await axios.post('http://localhost:5000/chatbot_assistance', formData, {
                headers: { 'Content-Type': 'multipart/form-data' }
            });

            setIsFileUploaded(true);
            setResponse(res.data.response || 'Dataset uploaded successfully! What would you like me to assist with?');
        } catch (error) {
            setResponse('Error uploading the dataset!');
            console.error(error);
        } finally {
            setIsLoading(false);
        }
    };

    // Function to handle query after file upload
    const handleQuerySubmit = async (event) => {
        event.preventDefault();

        if(!message) {
            setResponse('Please enter your query.');
            return;
        }

        setIsLoading(true);

        try {
            const res = await axios.post('http://localhost:5000/chatbot_assistance', { message });
            setResponse(res.data.response);
        } catch (error) {
            setResponse('Error processing your query!');
            console.error(error);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="chatbot-assistance-page-container">
            <header className="chatbot-assistance-report-header">
                <div className="chatbot-assistance-left-section">
                    <button onClick={handleBackToDashboard} className="chatbot-assistance-back-button">
                        Back
                    </button>
                </div>
                <div className="chatbot-assistance-right-section">
                    <span className="chatbot-assistance-date-time">
                        {currentDateTime.toLocaleString()}
                    </span>
                    <button onClick={handleLogout} className="chatbot-assistance-logout-button">
                        Logout
                    </button>
                </div>
            </header>

            <div className='chatbot-assistance-container'>
                <h2 className='chatbot-assistance-title'>APAnalyzer Chatbot Assistance</h2>
                {/* File Upload Section */}
                {!isFileUploaded && (
                    <form onSubmit={handleFileUpload} className="chatbot-assistance-upload-section">
                        <input
                            type='file'
                            onChange={handleFileChange}
                            accept='.csv'
                            className='chatbot-assistance-file-input'
                        />
                        <button 
                            type='submit'
                            disabled={isLoading}
                            className='chatbot-assistance-submit-button'
                        >
                            {isLoading ? 'Uploading...' : 'Upload Dataset'}
                        </button>
                    </form>
                )}

                {/* Chat Interaction Section */}
                {isFileUploaded && (
                    <form onSubmit={handleQuerySubmit} className='chatbot-assistance-form'>
                        <textarea
                            value={message}
                            onChange={(e) => setMessage(e.target.value)}
                            rows={4}
                            placeholder='Ask anything to our chatbot...?'
                            className='chatbot-assistance-textarea'
                        ></textarea>
                        <button 
                            type='submit'
                            disabled={isLoading}
                            className='chatbot-assistance-submit-button'
                        >
                            {isLoading ? 'Processing...' : 'Send it!'}
                        </button>
                    </form>
                )}

                {/* Response Display */}
                <div className='chatbot-assistance-response'>
                    <h3>Response: </h3>
                    <p>{response}</p>
                </div>
            </div>
        </div>
    );
};

export default ChatbotAssistance;