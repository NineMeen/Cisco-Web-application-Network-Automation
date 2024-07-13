from flask import Flask, render_template, request, session, redirect, url_for
from netmiko import ConnectHandler
import sqlite3 
import datetime

app = Flask(__name__)
app.secret_key = 'takta@1234'

@app.route('/')
def index():
    if 'logged_in' in session:
        return redirect(url_for('main'))
    else:
        return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'logged_in' in session:
        return redirect(url_for('main'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username == '1' and password == '1':
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('main'))

        conn = sqlite3.connect('user.db')
        c = conn.cursor()

        c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        user = c.fetchone()

        if user:
            # Login successful, set session variable
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('main'))
            
        else:
            # Login failed, display error message
            error = "Invalid username or password"
            return render_template('login.html', error=error)

    return render_template('login.html')


@app.route('/main')
def main():
    if 'logged_in' in session:
        return render_template('test.html')
    else:
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/ssh_connect', methods=['GET','POST'])
def ssh_connect():
    if request.method == 'POST':
        device_ip = request.form['device_ip']
        username = request.form['username']
        password = request.form['password']
        secret_pass = request.form.get('secret_pass')  # Use get() to handle missing field
        command = request.form['command']

        # Netmiko script for Linux using SSH key authentication
        device = {
            'device_type': 'cisco_ios',
            'ip': device_ip,
            'username': username,
            'password': password,
            'secret': secret_pass,
            'port': '22',
        }
        if secret_pass:
            device['secret'] = secret_pass  # Add secret only if provided

        try:
            with ConnectHandler(**device) as net_connect:
                output = net_connect.send_command(command)
        except Exception as e:
            output = f"Error: {str(e)}"

        return render_template('result.html', output=output)

@app.route('/backup_config', methods=['GET','POST'])
def backup_config():
    if request.method == 'GET':
        return render_template('backup_config.html')
    elif request.method == 'POST':
        device_ip = request.form['device_ip']
        username = request.form['username']
        password = request.form['password']
        secret_pass = request.form.get('secret_pass')  # Use get() to handle missing field

        device = {
            'device_type': 'cisco_ios',
            'ip': device_ip,
            'username': username,
            'password': password,
            'port': '22',
        }

        if secret_pass:
            device['secret'] = secret_pass  # Add secret only if provided

        backup_command = 'show running-config'
        try:
            with ConnectHandler(**device) as net_connect:
                net_connect.enable()  # Ensure you're in privileged exec mode to show running-config
                config_output = net_connect.send_command(backup_command)
                # Generate a filename with the current date and time
                filename = f"backup_{device_ip}_{datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
                with open(filename, 'w') as file:
                    file.write(config_output)
                output = f"Backup successful. Configuration saved to {filename}."
        except Exception as e:
            output = f"Error: {str(e)}"

        return render_template('result.html', output=output)

@app.route('/configure_acl', methods=['GET', 'POST'])
def configure_acl_route():
    if request.method == 'GET':
        return render_template('configure_acl.html')
    elif request.method == 'POST':
        device_ip = request.form['device_ip']
        username = request.form['username']
        password = request.form['password']
        secret_pass = request.form.get('secret_pass')  # Use get() to handle missing field
        acl_name = request.form['acl_name']
        acl_rules = request.form['acl_rules']  # Note the change here

        device = {
            'device_type': 'cisco_ios',
            'ip': device_ip,
            'username': username,
            'password': password,
            'secret': secret_pass,
            'port': '22',
        }

        if secret_pass:
            device['secret'] = secret_pass  # Add secret only if provided
            
        try:
            with ConnectHandler(**device) as net_connect:
                net_connect.enable()  # Ensure you're in privileged exec mode
                config_set = [f'ip access-list extended {acl_name}']
                config_set.extend(acl_rules.split('\n'))  # Split rules by newline
                net_connect.send_config_set(config_set)
                output = f"ACL configuration successful. Rules:\n{acl_rules}"
        except Exception as e:
            output = f"Error: {str(e)}"

        return render_template('configure_acl.html', output=output)

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=80, debug=True)






