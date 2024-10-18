# Cisco-Web-application-Network-Automation

# Network Automation Tool

This project is a web-based network automation tool for managing Cisco devices. It provides functionalities for device management, DHCP configuration, ACL management, interface configuration, and more.

## Requirements

- Python 3.7+
- Flask
- Flask-SocketIO
- Flask-Paginate
- Netmiko
- SQLite3 (included with Python)

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/NineMeen/Cisco-Web-application-Network-Automation.git
   cd Cisco-Web-application-Network-Automation
   ```

2. Create a virtual environment (optional but recommended):
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. Install the required packages:
   ```
   pip install -r requirements.txt
   ```

4. Set up the SQLite database:
   ```
   python setupdb.py
   ```

5. Run the application:
   ```
   python app.py
   ```

6. Access the application in your web browser at `http://localhost:8080`

