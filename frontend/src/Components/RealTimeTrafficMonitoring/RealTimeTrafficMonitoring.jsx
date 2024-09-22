import React, { useState, useEffect } from 'react';
import './RealTimeTrafficMonitoring.css';
import { useNavigate } from 'react-router-dom';
import io from 'socket.io-client';
import Swal from 'sweetalert2';

const RealTimeTrafficMonitoring = () => {
  const [currentDateTime, setCurrentDateTime] = useState(new Date());
  const navigate = useNavigate();
  const [trafficData, setTrafficData] = useState([]);  // State to store packet data
  const [filteredData, setFilteredData] = useState([]);  // State to store filtered packet data
  const [isCapturing, setIsCapturing] = useState(false); // State to track if capture is active
  const [socket, setSocket] = useState(null); // WebSocket instance

  // State for selected filter values (for each column)
  const [selectedFilters, setSelectedFilters] = useState({
    'Dst Port': [],
    'Protocol': []
  });

  // State to manage dropdown visibility
  const [dropdownOpen, setDropdownOpen] = useState({
    'Dst Port': false,
    'Protocol': false
  });

  useEffect(() => {
    // Timer to update current date-time every second
    const timer = setInterval(() => {
      setCurrentDateTime(new Date());
    }, 1000);

    return () => {
      clearInterval(timer);
    };
  }, []);  // Empty dependency array to run this effect only once

  // Initialize WebSocket and set up listeners when starting capture
  const startCapture = () => {
    const newSocket = io('http://localhost:5000');
    setSocket(newSocket);

    // Emit to start capturing packets
    newSocket.emit('start_capture');
    setIsCapturing(true);

    // Throttle the state updates to avoid excessive re-renders
    const handlePacketData = (packet) => {
      const parsedPacket = JSON.parse(packet);
      setTrafficData((prevData) => {
        const newData = [...prevData, parsedPacket];
        setFilteredData(newData);
        return newData;
      });
    };

    // Listen for real-time packet data
    newSocket.on('packet_data', handlePacketData);
  };

  // Stop packet capture and disconnect WebSocket
  const stopCapture = () => {
    if (socket) {
      socket.emit('stop_capture');
      socket.disconnect();
      setSocket(null);
      setIsCapturing(false);
    }
  };

  // Export table data to CSV file
  const exportToCSV = () => {
    Swal.fire({
      title: 'Export to CSV',
      input: 'text',
      inputLabel: 'Enter file name',
      inputPlaceholder: 'traffic_data',
      showCancelButton: true,
      confirmButtonText: 'Download',
      preConfirm: (fileName) => {
        return fetch('http://localhost:5000/export_csv', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ file_name: fileName || 'traffic_data' })
        })
        .then((response) => {
          if (!response.ok) {
            throw new Error('Failed to export CSV');
          }
          return response.blob();
        })
        .then((blob) => {
          const url = window.URL.createObjectURL(new Blob([blob]));
          const link = document.createElement('a');
          link.href = url;
          link.setAttribute('download', `${fileName || 'traffic_data'}.csv`);
          document.body.appendChild(link);
          link.click();
          document.body.removeChild(link);

          // Swal success message after download
          Swal.fire({
            icon: 'success',
            title: 'Success',
            text: 'CSV file has been saved successfully!',
            confirmButtonText: 'OK'
          });
        })
        .catch((error) => {
          Swal.showValidationMessage(`Request failed: ${error}`);
        });
      }
    });
  };

  // Toggle dropdown visibility for each column
  const toggleDropdown = (column) => {
    setDropdownOpen({
      ...dropdownOpen,
      [column]: !dropdownOpen[column]
    });
  };

  // Get unique values for dropdown filters
  const getUniqueValues = (column) => {
    return [...new Set(trafficData.map((row) => row[column]))].filter(Boolean);
  };

  // Handle filter changes for dropdown filters
  const handleFilterChange = (column, value) => {
    const updatedSelectedFilters = selectedFilters[column].includes(value)
      ? selectedFilters[column].filter((v) => v !== value)
      : [...selectedFilters[column], value];

    setSelectedFilters({
      ...selectedFilters,
      [column]: updatedSelectedFilters
    });
  };

  // Apply the filters to the traffic data
  useEffect(() => {
    let newFilteredData = [...trafficData];

    // Filter by selected values for each column
    Object.keys(selectedFilters).forEach((column) => {
      if (selectedFilters[column].length > 0) {
        newFilteredData = newFilteredData.filter((row) =>
          selectedFilters[column].includes(row[column])
        );
      }
    });

    setFilteredData(newFilteredData);
  }, [selectedFilters, trafficData]);

  const handleLogout = () => {
    if (socket) {
      socket.disconnect(); // Disconnect any active socket before logout
    }

    localStorage.removeItem('token');
    navigate('/');
  };

  const handleBackToDashboard = () => {
    navigate('/dashboard');
  };

  return (
    <div className="network-analysis-container">
      {/* Header Section */}
      <header className="network-header">
        <div className="left-section">
          <button onClick={handleBackToDashboard} className='back-button'>
            Back
          </button>
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
      <div className="main-content">
        <h2>Real Time Traffic Monitoring</h2>

        {/* Buttons to control capture */}
        <div className='capture-controls'>
          <button onClick={startCapture} disabled={isCapturing}>Start Capture</button>
          <button onClick={stopCapture} disabled={!isCapturing}>Stop Capture</button>
          <button onClick={exportToCSV} disabled={!trafficData.length}>Export to CSV</button>
        </div>

        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>
                  Destination Port
                  <span onClick={() => toggleDropdown('Dst Port')} className="filter-arrow">▼</span>
                  {dropdownOpen['Dst Port'] && (
                    <div className="dropdown-filter">
                      {getUniqueValues('Dst Port').map((value) => (
                        <label key={value}>
                          <input
                            type="checkbox"
                            checked={selectedFilters['Dst Port'].includes(value)}
                            onChange={() => handleFilterChange('Dst Port', value)}
                          />
                          {value}
                        </label>
                      ))}
                    </div>
                  )}
                </th>
                <th>
                  Protocol
                  <span onClick={() => toggleDropdown('Protocol')} className="filter-arrow">▼</span>
                  {dropdownOpen['Protocol'] && (
                    <div className="dropdown-filter">
                      {getUniqueValues('Protocol').map((value) => (
                        <label key={value}>
                          <input
                            type="checkbox"
                            checked={selectedFilters['Protocol'].includes(value)}
                            onChange={() => handleFilterChange('Protocol', value)}
                          />
                          {value}
                        </label>
                      ))}
                    </div>
                  )}
                </th>
                <th>Timestamp</th>
                <th>Flow Duration</th>
                <th>Tot Fwd</th>
                <th>Tot Fwd Pkts</th>
                <th>Tot Bwd Pkts</th>
                <th>TotLen Fwd Pkts</th>
                <th>TotLen Bwd Pkts</th>
                <th>Fwd Pkt Len Max</th>
                <th>Fwd Pkt Len Min</th>
                <th>Fwd Pkt Len Mean</th>
                <th>Fwd Pkt Len Std</th>
                <th>Bwd Pkt Len Max</th>
                <th>Bwd Pkt Len Min</th>
                <th>Bwd Pkt Len Mean</th>
                <th>Bwd Pkt Len Std</th>
                <th>Flow Byts/s</th>
                <th>Flow Pkts/s</th>
                <th>Flow IAT Mean</th>
                <th>Flow IAT Std</th>
                <th>Flow IAT Max</th>
                <th>Flow IAT Min</th>
                <th>Fwd IAT Tot</th>
                <th>Fwd IAT Mean</th>
                <th>Fwd IAT Std</th>
                <th>Fwd IAT Max</th>
                <th>Fwd IAT Min</th>
                <th>Bwd IAT Tot</th>
                <th>Bwd IAT Mean</th>
                <th>Bwd IAT Std</th>
                <th>Bwd IAT Max</th>
                <th>Bwd IAT Min</th>
                <th>Fwd PSH Flags</th>
                <th>Bwd PSH Flags</th>
                <th>Fwd URG Flags</th>
                <th>Bwd URG Flags</th>
                <th>Fwd Header Len</th>
                <th>Bwd Header Len</th>
                <th>Fwd Pkts/s</th>
                <th>Bwd Pkts/s</th>
                <th>Pkt Len Min</th>
                <th>Pkt Len Max</th>
                <th>Pkt Len Mean</th>
                <th>Pkt Len Std</th>
                <th>Pkt Len Var</th>
                <th>FIN Flag Cnt</th>
                <th>SYN Flag Cnt</th>
                <th>RST Flag Cnt</th>
                <th>PSH Flag Cnt</th>
                <th>ACK Flag Cnt</th>
                <th>URG Flag Cnt</th>
                <th>CWE Flag Count</th>
                <th>ECE Flag Cnt</th>
                <th>Down/Up Ratio</th>
                <th>Pkt Size Avg</th>
                <th>Fwd Seg Size Avg</th>
                <th>Bwd Seg Size Avg</th>
                <th>Fwd Byts/b Avg</th>
                <th>Fwd Pkts/b Avg</th>
                <th>Fwd Blk Rate Avg</th>
                <th>Bwd Byts/b Avg</th>
                <th>Bwd Pkts/b Avg</th>
                <th>Bwd Blk Rate Avg</th>
                <th>Subflow Fwd Pkts</th>
                <th>Subflow Fwd Byts</th>
                <th>Subflow Bwd Pkts</th>
                <th>Subflow Bwd Byts</th>
                <th>Init Fwd Win Byts</th>
                <th>Init Bwd Win Byts</th>
                <th>Fwd Act Data Pkts</th>
                <th>Fwd Seg Size Min</th>
                <th>Active Mean</th>
                <th>Active Std</th>
                <th>Active Max</th>
                <th>Active Min</th>
                <th>Idle Mean</th>
                <th>Idle Std</th>
                <th>Idle Max</th>
                <th>Idle Min</th>
                <th>Label</th>
              </tr>
            </thead>
            <tbody>
              {filteredData.map((packet, index) => (
                <tr key={index}>
                  <td>{index + 1}</td>
                  <td>{packet['Dst Port']}</td>
                  <td>{packet['Protocol']}</td>
                  <td>{packet['Timestamp']}</td>
                  <td>{packet['Flow Duration']}</td>
                  <td>{packet['Tot Fwd Pkts']}</td>
                  <td>{packet['Tot Bwd Pkts']}</td>
                  <td>{packet['TotLen Fwd Pkts']}</td>
                  <td>{packet['TotLen Bwd Pkts']}</td>
                  <td>{packet['Fwd Pkt Len Max']}</td>
                  <td>{packet['Fwd Pkt Len Min']}</td>
                  <td>{packet['Fwd Pkt Len Mean']}</td>
                  <td>{packet['Fwd Pkt Len Std']}</td>
                  <td>{packet['Bwd Pkt Len Max']}</td>
                  <td>{packet['Bwd Pkt Len Min']}</td>
                  <td>{packet['Bwd Pkt Len Mean']}</td>
                  <td>{packet['Bwd Pkt Len Std']}</td>
                  <td>{packet['Flow Byts/s']}</td>
                  <td>{packet['Flow Pkts/s']}</td>
                  <td>{packet['Flow IAT Mean']}</td>
                  <td>{packet['Flow IAT Std']}</td>
                  <td>{packet['Flow IAT Max']}</td>
                  <td>{packet['Flow IAT Min']}</td>
                  <td>{packet['Fwd IAT Tot']}</td>
                  <td>{packet['Fwd IAT Mean']}</td>
                  <td>{packet['Fwd IAT Std']}</td>
                  <td>{packet['Fwd IAT Max']}</td>
                  <td>{packet['Fwd IAT Min']}</td>
                  <td>{packet['Bwd IAT Tot']}</td>
                  <td>{packet['Bwd IAT Mean']}</td>
                  <td>{packet['Bwd IAT Std']}</td>
                  <td>{packet['Bwd IAT Max']}</td>
                  <td>{packet['Bwd IAT Min']}</td>
                  <td>{packet['Fwd PSH Flags']}</td>
                  <td>{packet['Bwd PSH Flags']}</td>
                  <td>{packet['Fwd URG Flags']}</td>
                  <td>{packet['Bwd URG Flags']}</td>
                  <td>{packet['Fwd Header Len']}</td>
                  <td>{packet['Bwd Header Len']}</td>
                  <td>{packet['Fwd Pkts/s']}</td>
                  <td>{packet['Bwd Pkts/s']}</td>
                  <td>{packet['Pkt Len Min']}</td>
                  <td>{packet['Pkt Len Max']}</td>
                  <td>{packet['Pkt Len Mean']}</td>
                  <td>{packet['Pkt Len Std']}</td>
                  <td>{packet['Pkt Len Var']}</td>
                  <td>{packet['FIN Flag Cnt']}</td>
                  <td>{packet['SYN Flag Cnt']}</td>
                  <td>{packet['RST Flag Cnt']}</td>
                  <td>{packet['PSH Flag Cnt']}</td>
                  <td>{packet['ACK Flag Cnt']}</td>
                  <td>{packet['URG Flag Cnt']}</td>
                  <td>{packet['CWE Flag Count']}</td>
                  <td>{packet['ECE Flag Cnt']}</td>
                  <td>{packet['Down/Up Ratio']}</td>
                  <td>{packet['Pkt Size Avg']}</td>
                  <td>{packet['Fwd Seg Size Avg']}</td>
                  <td>{packet['Bwd Seg Size Avg']}</td>
                  <td>{packet['Fwd Byts/b Avg']}</td>
                  <td>{packet['Fwd Pkts/b Avg']}</td>
                  <td>{packet['Fwd Blk Rate Avg']}</td>
                  <td>{packet['Bwd Byts/b Avg']}</td>
                  <td>{packet['Bwd Pkts/b Avg']}</td>
                  <td>{packet['Bwd Blk Rate Avg']}</td>
                  <td>{packet['Subflow Fwd Pkts']}</td>
                  <td>{packet['Subflow Fwd Byts']}</td>
                  <td>{packet['Subflow Bwd Pkts']}</td>
                  <td>{packet['Subflow Bwd Byts']}</td>
                  <td>{packet['Init Fwd Win Byts']}</td>
                  <td>{packet['Init Bwd Win Byts']}</td>
                  <td>{packet['Fwd Act Data Pkts']}</td>
                  <td>{packet['Fwd Seg Size Min']}</td>
                  <td>{packet['Active Mean']}</td>
                  <td>{packet['Active Std']}</td>
                  <td>{packet['Active Max']}</td>
                  <td>{packet['Active Min']}</td>
                  <td>{packet['Idle Mean']}</td>
                  <td>{packet['Idle Std']}</td>
                  <td>{packet['Idle Max']}</td>
                  <td>{packet['Idle Min']}</td>
                  <td>{packet['Label']}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default RealTimeTrafficMonitoring;