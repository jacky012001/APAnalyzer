import React, { useState, useEffect } from 'react';
import './MLModelTraining.css';
import { useNavigate } from 'react-router-dom';
import Swal from 'sweetalert2';
import io from 'socket.io-client';
import axios from 'axios';

const MLModelTraining = () => {
  const [currentDateTime, setCurrentDateTime] = useState(new Date());
  const [modelStatus, setModelStatus] = useState('Not Trained'); 
  const [realTimeModelStatus, setRealTimeModelStatus] = useState('Not Trained');
  const [isTraining, setIsTraining] = useState(false);
  const [isRealTimeTraining, setIsRealTimeTraining] = useState(false);
  const [socket, setSocket] = useState(null);
  const [comparisonResult, setComparisonResult] = useState(null);
  const [realTimeComparisonResult, setRealTimeComparisonResult] = useState(null);
  const [isComparisonCompleted, setIsComparisonCompleted] = useState(false);
  const [isRealTimeComparisonCompleted, setIsRealTimeComparisonCompleted] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentDateTime(new Date());
    }, 1000);

    return () => clearInterval(timer); // Clean up the interval on component unmount
  }, []);

  // Function to handle file input change (when user selects a file)
  const handleFileChange = async (event) => {
    const file = event.target.files[0]; // Get the selected file
    if (file) {
      const fileExtension = file.name.split('.').pop().toLowerCase(); // Extract file extension
      const validFileExtensions = ['csv']; // Only accept CSV files
      const validMimeType = ['text/csv'];

      // Validate file extension and MIME type
      if (validFileExtensions.includes(fileExtension) && validMimeType.includes(file.type)) {
        // Start training automatically after selecting a valid CSV file
        handleModelTraining(file); // Automatically trigger training
      } else {
        // Show error if file is not a CSV
        Swal.fire({
          title: 'Invalid File',
          text: 'Please upload a valid CSV file.',
          icon: 'error',
          confirmButtonText: 'OK',
        });
      }
    }
  };

  // Function to handle the CSV upload and trigger model training
  const handleModelTraining = async (file) => {
    try {
      // Check whether the model already exists
      const response = await axios.get('http://localhost:5000/check_model_exists');
      const { data } = response;
      
      if(data.exists) {
        Swal.fire({
          icon: 'info',
          title: 'Trained Model Information',
          html: `
            <p><strong>Model Parameters:</strong></p>
            <p>n_estimators: ${data.model_info.n_estimators}</p>
            <p>max_depth: ${data.model_info.max_depth || 'None'}</p>
            <p>min_samples_split: ${data.model_info.min_samples_split}</p>
            <p>min_samples_leaf: ${data.model_info.min_samples_leaf}</p>
            <br>
            <p><strong>Evaluation:</strong></p>
            <p>Accuracy: ${data.evaluation.accuracy || 'N/A'}</p>
          `,
          confirmButtonText: 'OK'
        });
        return;
      } else {
        Swal.fire({
          icon: 'error',
          title: 'Model not found',
          text: 'No trained model found. Please train the model first.',
        });
      }
    } catch (error) {
      Swal.fire({
        icon: 'error',
        title: 'Error!',
        text: 'Error loading the model!',
      });
    }

    if (file) {
      // Create FormData to upload the file
      const formData = new FormData();
      formData.append('file', file);

      try {
        setIsTraining(true); // Show loading/progress status
        setModelStatus('Uploading CSV and Starting Training...');

        // Send the file to the backend for processing and training
        await axios.post('http://localhost:5000/train_cicids2017', formData, {
          headers: {
            'Content-Type': 'multipart/form-data',
          },
        });

        // Notify the user that the training has started
        Swal.fire({
          icon: 'info',
          title: 'Training Started',
          text: 'The model training has started with Random Forest. Please wait...',
        });

        // Initialize the Socket.IO connection to receive training updates
        const newSocket = io('http://localhost:5000');
        setSocket(newSocket);

        // Listen for real-time training progress updates from the backend
        newSocket.on('training_progress', (data) => {
          setModelStatus(data.progress); // Update the model status as we receive progress
        });

        // Listen for training complete updates
        newSocket.on('training_complete', (data) => {
          setIsTraining(false); // Stop showing loading/progress
          setModelStatus('Trained Successfully!');
          Swal.fire({
            icon: 'success',
            title: 'Training Complete',
            text: 'The CICIDS2017 model has been trained successfully using Random Forest!',
          });

          // Disconnect the socket when the training is complete
          newSocket.disconnect();
          setSocket(null); // Clear socket reference
        });
      } catch (error) {
        setIsTraining(false); // Stop loading/progress on error
        Swal.fire({
          icon: 'error',
          title: 'Training Failed',
          text: 'There was an error uploading the dataset or during the training process.',
        });
      }
    }
  };

  // Function to handle file input change and start dataset comparison
  const handleDatasetFileChange = async (event) => {
    const file = event.target.files[0];
    if (file) {
      const fileExtension = file.name.split('.').pop().toLowerCase(); // Extract file extension
      const validFileExtensions = ['csv']; // Only accept CSV files
      const validMimeType = ['text/csv'];

      // Validate file extension and MIME type
      if (validFileExtensions.includes(fileExtension) && validMimeType.includes(file.type)) {
        // Start comparison automatically after selecting a valid CSV file
        handleCompareDataset(file);
      } else {
        // Show error if file is not a CSV
        Swal.fire({
          title: 'Invalid File',
          text: 'Please upload a valid CSV file.',
          icon: 'error',
          confirmButtonText: 'OK',
        });
      }
    }
  };

  // Function to handle real-time file input change and start dataset comparison
  const handleRealTimeDatasetFileChange = async (event) => {
    const file = event.target.files[0];
    if (file) {
      const fileExtension = file.name.split('.').pop().toLowerCase(); // Extract file extension
      const validFileExtensions = ['csv']; // Only accept CSV files
      const validMimeType = ['text/csv'];

      // Validate file extension and MIME type
      if (validFileExtensions.includes(fileExtension) && validMimeType.includes(file.type)) {
        // Start comparison automatically after selecting a valid CSV file
        handleCompareRealTimeDataset(file);
      } else {
        // Show error if file is not a CSV
        Swal.fire({
          title: 'Invalid File',
          text: 'Please upload a valid CSV file.',
          icon: 'error',
          confirmButtonText: 'OK',
        });
      }
    }
  };

  // Function to handle dataset comparison
  const handleCompareDataset = async (file) => {
    if (!file) return;

    // Create FormData to upload file
    const formData = new FormData();
    formData.append('file', file);

    try {
      setIsTraining(true);
      setModelStatus('Uploading CSV and Starting Comparison...');

      // Send the file to the backend for comparison
      const response = await axios.post('http://localhost:5000/compare_dataset', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });

      // Extract the result from backend response
      const { precision, recall, anomalies_detected, severity_breakdown, low_severity_threats, medium_severity_threats, high_severity_threats } = response.data;

      // Update the comparison result and model status
      setComparisonResult({
        precision: precision ? precision.toFixed(2) : 'N/A (No True Label)',
        recall: recall ? recall.toFixed(2) : 'N/A (No True Label)',
        anomalies_detected: anomalies_detected || 0,
        severity_breakdown: severity_breakdown || { low: 0, medium: 0, high: 0 },
        low_severity_threats: low_severity_threats || [],
        medium_severity_threats: medium_severity_threats || [],
        high_severity_threats: high_severity_threats || [],
      });

      setModelStatus('Comparison Completed');
      setIsTraining(false); // Stop showing progress
      setIsComparisonCompleted(true); // Set comparison as completed
    } catch(error) {
      setIsTraining(false); // Stop showing progress
      setModelStatus('Comparison Failed');
      Swal.fire({
        icon: 'error',
        title: 'Comparison Failed',
        text: 'There was an error during the dataset comparison process.',
      });
    }
  };

  // Function to handle real-time dataset comparison
  const handleCompareRealTimeDataset = async (file) => {
    if (!file) return;

    // Create FormData to upload file
    const formData = new FormData();
    formData.append('file', file);

    try {
      setIsRealTimeTraining(true);
      setRealTimeModelStatus('Uploading CSV and Starting Comparison...');

      // Send the file to the backend for comparison
      const response = await axios.post('http://localhost:5000/compare_real_time_dataset', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });

      // Extract the result from backend response
      const { predicted_labels, anomalies_detected, severity_breakdown, low_severity_threats, medium_severity_threats, high_severity_threats } = response.data;

      // Update the comparison result and model status
      setRealTimeComparisonResult({
        predicted_labels: predicted_labels || [],
        anomalies_detected: anomalies_detected || 0,
        severity_breakdown: severity_breakdown || { low: 0, medium: 0, high: 0 },
        low_severity_threats: low_severity_threats || [],
        medium_severity_threats: medium_severity_threats || [],
        high_severity_threats: high_severity_threats || [],
      });

      setRealTimeModelStatus('Comparison Completed');
      setIsRealTimeTraining(false); // Stop showing progress
      setIsRealTimeComparisonCompleted(true); // Set comparison as completed
    } catch(error) {
      setIsRealTimeTraining(false); // Stop showing progress
      setRealTimeModelStatus('Comparison Failed');
      Swal.fire({
        icon: 'error',
        title: 'Comparison Failed',
        text: 'There was an error during the dataset comparison process.',
      });
    }
  };

  // Handler for "Train Dataset?" button to trigger file input click
  const handleTrainDataset = () => {
    document.getElementById('fileInput').click(); // Programmatically click hidden input
  };

  // Handler for "Compare Dataset" button to trigger file input click
  const handleCompareDatasetClick = () => {
    document.getElementById('datasetFileInput').click();
  }

  // Another Handler for "Compare Dataset" button to trigger real-time file input click
  const handleCompareRealTimeDatasetClick = () => {
    document.getElementById('realTimeDatasetFileInput').click();
  }

  // Logout function
  const handleLogout = () => {
    if (socket) {
      socket.disconnect(); // Disconnect any active socket before logout
    }

    localStorage.removeItem('token'); // Clear token (or other auth details)
    navigate('/'); // Redirect back to the login page
  };

  const handleBackToDashboard = () => {
    navigate('/dashboard');
  };

  return (
    <div className="ml-model-training-container">
      {/* Header Section */}
      <header className="ml-model-training-header">
        <div className="left-section">
          <button onClick={handleBackToDashboard} className='model-back-button'>
            Back
          </button>
          <button onClick={handleTrainDataset} className="train-dataset-button">
            Train CICIDS2017 Dataset
          </button>
          <input
            type="file"
            id="fileInput"
            style={{ display: 'none' }}
            accept=".csv"
            onChange={handleFileChange} // Automatically start training after file upload
          />
        </div>
        <div className="right-section">
          <span className="date-time">
            {currentDateTime.toLocaleString()}
          </span>
          <button onClick={handleLogout} className="logout-button">
            Logout
          </button>
        </div>
      </header>

      {/* Main Content Section */}
      <div className="ml-model-training-main-content">
        <div className="ml-model-training-content-box first-box">
          <h2>First Dataset Comparison</h2>
          <p>Status: {modelStatus}</p>

          {/* Upload Dataset Button inside first box */}
          <button onClick={handleCompareDatasetClick} className='upload-dataset-button' disabled={isTraining || isComparisonCompleted}>
            {isTraining ? 'Processing...' : 'Upload Dataset'}
          </button>
          <input
            type='file'
            id='datasetFileInput'
            style={{ display: 'none' }}
            accept='.csv'
            onChange={handleDatasetFileChange} // Automatically start comparison after file uploaded
          />

          {/* Display comparison results here */}
          {comparisonResult && (
            <div className="comparison-results">
              <p>Precision: {comparisonResult.precision}</p>
              <p>Recall: {comparisonResult.recall}</p>
              <p>Anomalies Detected: {comparisonResult.anomalies_detected}</p>
              <p>Severity Breakdown:</p>
              <h3>Low Severity Threats: {comparisonResult.severity_breakdown.low}</h3>
              <ul className='threat-list'>
                {comparisonResult.low_severity_threats && comparisonResult.low_severity_threats.length > 0 ? (
                  comparisonResult.low_severity_threats.map((threat, index) => (
                    <li key={index} className='threat-item'>
                      <strong>Threat {index + 1}:</strong>
                      <div className='threat-details'>
                        <ol>
                          {Object.entries(threat).map(([key, value], subIndex) => (
                            <li key={subIndex}>
                              <span className='key-bold'>{key}:</span>
                              <span className='value-normal'> {value !== null ? value : 'N/A'}</span>
                            </li>
                          ))}
                        </ol>
                      </div>
                    </li>
                  ))
                ) : (
                  <p>No low severity threats detected.</p>
                )}
              </ul>

              <h3>Medium Severity Threats: {comparisonResult.severity_breakdown.medium}</h3>
              <ul className='threat-list'>
                {comparisonResult.medium_severity_threats && comparisonResult.medium_severity_threats.length > 0 ? (
                  comparisonResult.medium_severity_threats.map((threat, index) => (
                    <li key={index} className='threat-item'>
                      <strong>Threat {index + 1}:</strong>
                      <div className='threat-details'>
                        <ol>
                          {Object.entries(threat).map(([key, value], subIndex) => (
                            <li key={subIndex}>
                              <span className='key-bold'>{key}:</span>
                              <span className='value-normal'> {value !== null ? value : 'N/A'}</span>
                            </li>
                          ))}
                        </ol>
                      </div>
                    </li>
                  ))
                ) : (
                  <p>No medium severity threats detected.</p>
                )}
              </ul>

              <h3>High Severity Threats: {comparisonResult.severity_breakdown.high}</h3>
              <ul className='threat-list'>
                {comparisonResult.high_severity_threats && comparisonResult.high_severity_threats.length > 0 ? (
                  comparisonResult.high_severity_threats.map((threat, index) => (
                    <li key={index} className='threat-item'>
                      <strong>Threat {index + 1}:</strong>
                      <div className='threat-details'>
                        <ol>
                          {Object.entries(threat).map(([key, value], subIndex) => (
                            <li key={subIndex}>
                              <span className='key-bold'>{key}:</span>
                              <span className='value-normal'> {value !== null ? value : 'N/A'}</span>
                            </li>
                          ))}
                        </ol>
                      </div>
                    </li>
                  ))
                ) : (
                  <p>No high severity threats detected.</p>
                )}
              </ul>
            </div>
          )}
        </div>

        <div className="ml-model-training-content-box second-box">
          <h2>Real Time Dataset Comparison</h2>
          <p>Status: {realTimeModelStatus}</p>

          {/* Upload Dataset Button inside second box */}
          <button onClick={handleCompareRealTimeDatasetClick} className='upload-dataset-button' disabled={isRealTimeTraining || isRealTimeComparisonCompleted}>
            {isRealTimeTraining ? 'Processing...' : 'Upload Dataset'}
          </button>
          <input
            type='file'
            id='realTimeDatasetFileInput'
            style={{ display: 'none' }}
            accept='.csv'
            onChange={handleRealTimeDatasetFileChange} // Automatically start comparison after file uploaded
          />

          {/* Display comparison results here */}
          {realTimeComparisonResult && (
            <div className="comparison-results">
              <p>Anomalies Detected: {realTimeComparisonResult.anomalies_detected}</p>
              <p>Severity Breakdown:</p>
              <h3>Predicted Labels:</h3>
              <ul className='predicted-labels-list'>
                {realTimeComparisonResult.predicted_labels && realTimeComparisonResult.predicted_labels.length > 0 ? (
                  // Group labels by their occurrence
                  Object.entries(
                    realTimeComparisonResult.predicted_labels.reduce((acc, labelObj) => {
                      const label = labelObj['Predicted Label'] || 'N/A';
                      acc[label] = (acc[label] || 0) + 1; // Count occurrences of each label
                      return acc;
                    }, {})
                  ).map(([label, count], index) => (
                    <li key={index}>
                      Predicted Label: {label} {count > 1 && `(x${count})`}
                    </li>
                  ))
                ) : (
                  <p>No labels predicted.</p>
                )}
              </ul>
              
              <h3>Low Severity Threats: {realTimeComparisonResult.severity_breakdown.low}</h3>
              <ul className='threat-list'>
                {realTimeComparisonResult.low_severity_threats && realTimeComparisonResult.low_severity_threats.length > 0 ? (
                  realTimeComparisonResult.low_severity_threats.map((threat, index) => (
                    <li key={index} className='threat-item'>
                      <strong>Threat {index + 1}:</strong>
                      <div className='threat-details'>
                        <ol>
                          {Object.entries(threat).map(([key, value], subIndex) => (
                            <li key={subIndex}>
                              <span className='key-bold'>{key}:</span>
                              <span className='value-normal'> {value !== null ? value : 'N/A'}</span>
                            </li>
                          ))}
                        </ol>
                      </div>
                    </li>
                  ))
                ) : (
                  <p>No low severity threats detected.</p>
                )}
              </ul>

              <h3>Medium Severity Threats: {realTimeComparisonResult.severity_breakdown.medium}</h3>
              <ul className='threat-list'>
                {realTimeComparisonResult.medium_severity_threats && realTimeComparisonResult.medium_severity_threats.length > 0 ? (
                  realTimeComparisonResult.medium_severity_threats.map((threat, index) => (
                    <li key={index} className='threat-item'>
                      <strong>Threat {index + 1}:</strong>
                      <div className='threat-details'>
                        <ol>
                          {Object.entries(threat).map(([key, value], subIndex) => (
                            <li key={subIndex}>
                              <span className='key-bold'>{key}:</span>
                              <span className='value-normal'> {value !== null ? value : 'N/A'}</span>
                            </li>
                          ))}
                        </ol>
                      </div>
                    </li>
                  ))
                ) : (
                  <p>No medium severity threats detected.</p>
                )}
              </ul>

              <h3>High Severity Threats: {realTimeComparisonResult.severity_breakdown.high}</h3>
              <ul className='threat-list'>
                {realTimeComparisonResult.high_severity_threats && realTimeComparisonResult.high_severity_threats.length > 0 ? (
                  realTimeComparisonResult.high_severity_threats.map((threat, index) => (
                    <li key={index} className='threat-item'>
                      <strong>Threat {index + 1}:</strong>
                      <div className='threat-details'>
                        <ol>
                          {Object.entries(threat).map(([key, value], subIndex) => (
                            <li key={subIndex}>
                              <span className='key-bold'>{key}:</span>
                              <span className='value-normal'> {value !== null ? value : 'N/A'}</span>
                            </li>
                          ))}
                        </ol>
                      </div>
                    </li>
                  ))
                ) : (
                  <p>No high severity threats detected.</p>
                )}
              </ul>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default MLModelTraining;
