# Security Log Analysis Tool

A Python-based cybersecurity log analysis tool that processes large authentication datasets to detect brute-force login attempts, identify malicious IP addresses, analyze attack locations, and visualize authentication attack patterns.

The tool parses authentication logs containing millions of events and performs automated threat analysis including attacker ranking, geographic attack analysis, and attack timeline visualization.

## Key Features

* Detect brute-force login attacks from authentication logs
* Identify top attacking IP addresses
* Analyze attack origins by city/location
* Detect attack spikes across different hours of the day
* Visualize attack patterns using graphs
* Generate automated security reports
* Export attacker data for further investigation

## Technologies Used

* Python
* CSV log parsing
* Data visualization with Matplotlib
* Security event analysis
* Command-line automation


## Example Visualizations

### Top Attacking IPs
![Attackers](screenshots/attackers.png)

### Attack Locations
![Cities](screenshots/cities.png)

### Attack Timeline
![Timeline](screenshots/timeline.png)



## Usage

Run log analysis:

python analyzer.py analyze auth_log.csv

Start real-time monitoring:

python analyzer.py monitor auth_log.csv

Launch the dashboard:

python analyzer.py dashboard



## Dataset

A small sample authentication log is included in the `data` folder for testing.

The tool was originally designed to analyze large authentication log datasets with millions of events.

Users can upload their own authentication log CSV files containing the following fields:

timestamp, source_ip, city, username, service, attempts, status, port, protocol