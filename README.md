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
   ```

2. Create a virtual environment (optional but recommended):
   ```
   cd Cisco-Web-application-Network-Automation
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. Install the required packages:
   ```
   pip install -r requirements.txt
   ```

4. Set up the SQLite database:
   You will be prompted to set a password for the default admin user. You can also pass credentials using the `ADMIN_USERNAME` and `ADMIN_PASSWORD` environment variables.
   ```
   python setupdb.py
   ```

5. Run the application:
   ```
   python app.py
   ```

6. Access the application in your web browser at `http://localhost:8080`
7. Login with the user and password you configured during setup (default username: `admin`).

