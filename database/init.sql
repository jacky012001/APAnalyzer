-- Create a table for storing network traffic data
CREATE TABLE Network_Traffic(
    traffic_time TIMESTAMP NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    traffic_id SERIAL PRIMARY KEY,
    destination_ip VARCHAR(45) NOT NULL,
    instance_protocol VARCHAR(10) NOT NULL,
    instance_length INT NOT NULL,
    instance_info TEXT NOT NULL
);
-- Create a table for storing detected threats
CREATE TABLE Threats(
    threat_id SERIAL PRIMARY KEY,
    traffic_id INT NOT NULL REFERENCES Network_Traffic(traffic_id),
    threat_time TIMESTAMP NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    threat_type VARCHAR(50) NOT NULL,
    severity VARCHAR(10) NOT NULL,
    threat_description TEXT NOT NULL
);