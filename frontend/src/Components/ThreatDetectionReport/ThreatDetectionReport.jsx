import React, { useState, useEffect } from 'react';
import './ThreatDetectionReport.css';
import axios from 'axios';
import Swal from 'sweetalert2';
import { useNavigate } from 'react-router-dom';

const ThreatDetectionReport = () => {
    const [currentDateTime, setCurrentDateTime] = useState(new Date());
    const [file, setFile] = useState(null);
    const [reportData, setReportData] = useState(null);
    const [isLoading, setIsLoading] = useState(false);
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

    const handleFileChange = (event) => {
        setFile(event.target.files[0]);
    };

    const generateReport = async () => {
        if (!file) {
            Swal.fire({
                icon: 'error',
                title: 'No File Selected',
                text: 'Please select a dataset to generate a report.',
            });
            return;
        }

        const formData = new FormData();
        formData.append('file', file);

        try {
            setIsLoading(true);
            const response = await axios.post('http://localhost:5000/generate_report', formData, {
                headers: {
                    'Content-Type': 'multipart/form-data',
                },
            });
            setReportData(response.data);
            setIsLoading(false);
        } catch (error) {
            setIsLoading(false);
            Swal.fire({
                icon: 'error',
                title: 'Error Generating Report',
                text: 'There was an error processing the dataset. Please try again.',
            });
        }
    };

    return (
        <div className="threat-detection-report-page-container">
            <header className="threat-detection-report-header">
                <div className="threat-detection-report-left-section">
                    <button onClick={handleBackToDashboard} className="threat-detection-report-back-button">
                        Back
                    </button>
                </div>
                <div className="threat-detection-report-right-section">
                    <span className="threat-detection-report-date-time">
                        {currentDateTime.toLocaleString()}
                    </span>
                    <button onClick={handleLogout} className="threat-detection-report-logout-button">
                        Logout
                    </button>
                </div>
            </header>

            <div className='threat-detection-report-container'>
                <h1 className='threat-detection-report-title'>Threat Detection & Solution Report</h1>

                <div className='threat-detection-report-upload-section'>
                    <input
                        type='file'
                        accept='.csv'
                        onChange={handleFileChange}
                        className='threat-detection-report-file-input'
                    />
                    <button
                        onClick={generateReport}
                        disabled={isLoading}
                        className='threat-detection-report-generate-button'
                    >
                        {isLoading ? 'Generating Report...' : 'Generate Report'}
                    </button>
                </div>

                {reportData && (
                    <div className="threat-detection-report-section">
                        <img src="./logo.png" alt="APAnalyzer Logo" className="logo" />
                        <h2 className="threat-detection-report-summary-title">Report Summary</h2>

                        <div className="threat-detection-report-summary">
                            <p><strong>File Processed:</strong> {file.name}</p>
                            <p><strong>Total Threats Detected:</strong> {reportData.totalThreats}</p>
                            <p><strong>Threat Types:</strong></p>
                            <ol className="threat-detection-report-threat-list">
                                {reportData.threats.map((threat, index) => (
                                    <li key={index} className="threat-detection-report-threat-item">
                                        <strong>{threat.name}</strong>
                                        <ul className='threat-detection-report-threat-details'>
                                            <li><strong>Severity:</strong> {threat.severity}</li>
                                            <li><strong>Explanation:</strong> {threat.explanation}</li>
                                            <li><em>Proposed Solution:</em> {threat.solution}</li>
                                        </ul>
                                    </li>
                                ))}
                            </ol>
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
};

export default ThreatDetectionReport;