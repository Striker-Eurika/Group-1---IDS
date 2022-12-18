USE intrusion_db;

CREATE TABLE attack(
	attack_id INT PRIMARY KEY,
	attack_type VARCHAR(64)
);

CREATE TABLE intrusion(
	intrusion_id INT AUTO_INCREMENT PRIMARY KEY,
	attack_id INT,
	time_of_detection DATETIME DEFAULT NOW()
	FOREIGN KEY (attack_id) REFERENCES attack(attack_id)
);

INSERT INTO attack(attack_id, attack_type) VALUES
	(1, 'DDoS'),
	(2, 'PortScan'),
	(3, 'Bot'),
	(4, 'Infiltration'),
	(5, 'Brute Force'),
	(6, 'XSS'),
	(7, 'Sql Injection'),
	(8, 'FTP-Patator'),
	(9, 'SSH-Patator'),
	(10, 'DoS slowloris'),
	(11, 'DoS Slowhttptest'),
	(12, 'DoS Hulk'),
	(13, 'DoS GoldenEye'),
	(14, 'Heartbleed');
