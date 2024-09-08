import math
from flask import Flask, render_template, request, session, redirect, url_for, flash, send_file, jsonify
from flask_socketio import SocketIO, emit
from flask_paginate import Pagination, get_page_args
from netmiko import ConnectHandler
import sqlite3
from logger import log_event
import datetime
from io import BytesIO
import re
from collections import defaultdict

app = Flask(__name__)
app.secret_key = 'takta@1234'
socketio = SocketIO(app)

# Create a log table in the database
conn = sqlite3.connect('user.db')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS log
             (id INTEGER PRIMARY KEY, event TEXT, username TEXT, timestamp TEXT)''')
conn.commit()
conn.close()



def get_device_info(device_id):
    conn = sqlite3.connect('device.db')
    cursor = conn.cursor()
    cursor.execute("SELECT device_type, ip_address, user, password FROM router_device WHERE id=?", (device_id,))
    device_info = cursor.fetchone()
    conn.close()
    if device_info:
        return {
            'device_type': device_info[0],
            'ip': device_info[1],
            'username': device_info[2],
            'password': device_info[3],
        }
    return None


@app.route('/')
def index():
    if 'logged_in' in session: #เช็คล๋็อคอินเซสชั่นว่ามีไหม ถ้ามีไป main ถ้าไม่ ไป login
        return redirect(url_for('main'))
    else:
        return redirect(url_for('login'))

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
            log_event('Login successful', username)
            return redirect(url_for('main'))

        conn = sqlite3.connect('user.db')
        c = conn.cursor()

        c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        user = c.fetchone()

        if user:
            # Login successful, set session variable
            session['logged_in'] = True
            session['username'] = username
            log_event('Login successful', username)
            return redirect(url_for('main'))

        else:
            # Login failed, display error message
            error = "Invalid username or password"
            return render_template('login.html', error=error)
            # return redirect(url_for('login', error=error))
        

    return render_template('login.html')

@app.route('/logout')
def logout():
    username = session.get('username')
    session.pop('logged_in', None)
    session.pop('username', None)
    log_event('Logout', username)
    return redirect(url_for('login'))

@app.route('/main')
def main():
    if 'logged_in' in session:
        return render_template('main2.html')       
    else:
        return redirect(url_for('login'))

@app.route('/router/device', defaults={'page': 1})
@app.route('/router/device/<int:page>')
def router_device(page):
    if 'logged_in' in session:
        conn = sqlite3.connect('device.db')
        c = conn.cursor()
        c.execute("SELECT * FROM router_device")
        all_router_device = c.fetchall()
        conn.close()

        per_page = 10
        offset = (page - 1) * per_page
        paginated_router_device = all_router_device[offset:offset + per_page]

        return render_template('router_devices.html', router_device=paginated_router_device, page=page, per_page=per_page, total_pages=(len(all_router_device) + per_page - 1) // per_page)
    else:
        return redirect(url_for('login'))
    
@app.route('/switchlayer2/device', defaults={'page': 1})
@app.route('/switchlayer2/device/<int:page>')
def sl2_device(page):
    if 'logged_in' in session:
        conn = sqlite3.connect('device.db')
        c = conn.cursor()
        c.execute("SELECT * FROM sl2_device")
        all_sl2_device = c.fetchall()
        conn.close()

        per_page = 10
        offset = (page - 1) * per_page
        paginated_sl2_device = all_sl2_device[offset:offset + per_page]

        return render_template('sl2_devices.html', sl2_device=paginated_sl2_device, page=page, per_page=per_page, total_pages=(len(all_sl2_device) + per_page - 1) // per_page)
    else:
        return redirect(url_for('login'))
    
@app.route('/switchlayer3/device', defaults={'page': 1})
@app.route('/switchlayer3/device/<int:page>')
def sl3_device(page):
    if 'logged_in' in session:
        conn = sqlite3.connect('device.db')
        c = conn.cursor()
        c.execute("SELECT * FROM sl3_device")
        all_sl3_device = c.fetchall()
        conn.close()

        per_page = 10
        offset = (page - 1) * per_page
        paginated_sl3_device = all_sl3_device[offset:offset + per_page]

        return render_template('sl3_devices.html', router_device=paginated_sl3_device, page=page, per_page=per_page, total_pages=(len(all_sl3_device) + per_page - 1) // per_page)
    else:
        return redirect(url_for('login'))


@app.route('/add/device/router',methods=['GET','POST'])
def add_device_router():
    page = int(request.args.get('page', 1))
    if 'logged_in' in session:
        if request.method == 'POST':
            device_type = request.form['device_type']
            ip_address = request.form['ip_address']
            user = request.form['user']
            password = request.form['password']
            secret_password = request.form['secret_password']
            hostname = request.form['hostname']

            conn = sqlite3.connect('device.db')
            c = conn.cursor()
            
            # Check if device already exists
            c.execute("SELECT * FROM router_device WHERE hostname=? AND ip_address=? AND user=?", (hostname, ip_address, user))
            existing_device = c.fetchone()
            if existing_device:
                flash('Device data already exists in the database')
                # username = session.get('username')
                log_event('Device creation failed (duplicate)',session.get('username'))
                return render_template('router_add_devices.html')

            now = datetime.datetime.now()
            date_add = now.strftime("%d-%m-%Y %H:%M:%S")
            c.execute(
                "INSERT INTO router_device (device_type, ip_address, user, password, secret_password, hostname, date_add) VALUES (?,?,?,?,?,?,?)", 
                      (device_type, 
                       ip_address, 
                       user, 
                       password, 
                       secret_password, 
                       hostname, 
                       date_add,
                       ),
                       )
            conn.commit()
            conn.close()
            log_event(f"Router Device created: {hostname} ({ip_address})", session.get('username'))
            return redirect(url_for('router_device'))
        return render_template('router_add_devices.html')
    else:
        return redirect(url_for('login'))

@app.route('/add/device/swichlayer2',methods=['GET','POST'])
def add_device_sl2devices():
    page = int(request.args.get('page', 1))
    if 'logged_in' in session:
        if request.method == 'POST':
            device_type = request.form['device_type']
            ip_address = request.form['ip_address']
            user = request.form['user']
            password = request.form['password']
            secret_password = request.form['secret_password']
            hostname = request.form['hostname']

            conn = sqlite3.connect('device.db')
            c = conn.cursor()
            
            # Check if device already exists
            c.execute("SELECT * FROM sl2_device WHERE hostname=? AND ip_address=? AND user=?", (hostname, ip_address, user))
            existing_device = c.fetchone()
            if existing_device:
                flash('Device data already exists in the database')
                # username = session.get('username')
                log_event('Device creation failed (duplicate)',session.get('username'))
                return render_template('sl2_add_devices.html')

            now = datetime.datetime.now()
            date_add = now.strftime("%d-%m-%Y %H:%M:%S")
            c.execute(
                "INSERT INTO sl2_device (device_type, ip_address, user, password, secret_password, hostname, date_add) VALUES (?,?,?,?,?,?,?)", 
                      (device_type, 
                       ip_address, 
                       user, 
                       password, 
                       secret_password, 
                       hostname, 
                       date_add,
                       ),
                       )
            conn.commit()
            conn.close()
            log_event(f"Switch L2 Device created: {hostname} ({ip_address})", session.get('username'))
            return redirect(url_for('sl2_device'))
        return render_template('sl2_add_devices.html')
    else:
        return redirect(url_for('login'))


@app.route('/add/device/switchlayer3',methods=['GET','POST'])
def add_device_sl3devices():
    page = int(request.args.get('page', 1))
    if 'logged_in' in session:
        if request.method == 'POST':
            device_type = request.form['device_type']
            ip_address = request.form['ip_address']
            user = request.form['user']
            password = request.form['password']
            secret_password = request.form['secret_password']
            hostname = request.form['hostname']

            conn = sqlite3.connect('device.db')
            c = conn.cursor()
            
            # Check if device already exists
            c.execute("SELECT * FROM sl3_device WHERE hostname=? AND ip_address=? AND user=?", (hostname, ip_address, user))
            existing_device = c.fetchone()
            if existing_device:
                flash('Device data already exists in the database')
                # username = session.get('username')
                log_event('Device creation failed (duplicate)',session.get('username'))
                return render_template('sl3_add_devices.html')

            now = datetime.datetime.now()
            date_add = now.strftime("%d-%m-%Y %H:%M:%S")
            c.execute(
                "INSERT INTO sl2_device (device_type, ip_address, user, password, secret_password, hostname, date_add) VALUES (?,?,?,?,?,?,?)", 
                      (device_type, 
                       ip_address, 
                       user, 
                       password, 
                       secret_password, 
                       hostname, 
                       date_add,
                       ),
                       )
            conn.commit()
            conn.close()
            log_event(f"Switch L3 Device created: {hostname} ({ip_address})", session.get('username'))
            return redirect(url_for('router_device'))
        return render_template('sl2_add_devices.html')
    else:
        return redirect(url_for('login'))


@app.route('/edit/device/router/<int:id>', methods=['GET', 'POST'])
def edit_device_router(id):
    if 'logged_in' in session:
        conn = sqlite3.connect('device.db')
        c = conn.cursor()
        
        if request.method == 'POST':
            device_type = request.form['device_type']
            ip_address = request.form['ip_address']
            user = request.form['user']
            password = request.form['password']
            secret_password = request.form['secret_password']
            hostname = request.form['hostname']
            
            c.execute("""UPDATE router_device 
                         SET device_type=?, ip_address=?, user=?, password=?, secret_password=?, hostname=? 
                         WHERE id=?""", 
                      (device_type, ip_address, user, password, secret_password, hostname, id))
            conn.commit()
            flash('Device updated successfully')
            return redirect(url_for('router_device'))
        
        c.execute("SELECT * FROM router_device WHERE id=?", (id,))
        device = c.fetchone()
        conn.close()
        
        if device:
            return render_template('edit_device_router.html', device=device)
        else:
            flash('Device not found')
            return redirect(url_for('router_device'))
    else:
        return redirect(url_for('login'))

@app.route('/edit/device/switchlayer2/<int:id>', methods=['GET', 'POST'])
def edit_device_sl2(id):
    if 'logged_in' in session:
        conn = sqlite3.connect('device.db')
        c = conn.cursor()
        
        if request.method == 'POST':
            device_type = request.form['device_type']
            ip_address = request.form['ip_address']
            user = request.form['user']
            password = request.form['password']
            secret_password = request.form['secret_password']
            hostname = request.form['hostname']
            
            c.execute("""UPDATE sl2_device 
                         SET device_type=?, ip_address=?, user=?, password=?, secret_password=?, hostname=? 
                         WHERE id=?""", 
                      (device_type, ip_address, user, password, secret_password, hostname, id))
            conn.commit()
            flash('Device updated successfully')
            return redirect(url_for('sl2_device'))
        
        c.execute("SELECT * FROM sl2_device WHERE id=?", (id,))
        device = c.fetchone()
        conn.close()
        
        if device:
            return render_template('edit_device_sl2.html', device=device)
        else:
            flash('Device not found')
            return redirect(url_for('sl2_device'))
    else:
        return redirect(url_for('login'))
    
@app.route('/edit/device/switchlayer3/<int:id>', methods=['GET', 'POST'])
def edit_device_sl3(id):
    if 'logged_in' in session:
        conn = sqlite3.connect('device.db')
        c = conn.cursor()
        
        if request.method == 'POST':
            device_type = request.form['device_type']
            ip_address = request.form['ip_address']
            user = request.form['user']
            password = request.form['password']
            secret_password = request.form['secret_password']
            hostname = request.form['hostname']
            
            c.execute("""UPDATE sl3_device 
                         SET device_type=?, ip_address=?, user=?, password=?, secret_password=?, hostname=? 
                         WHERE id=?""", 
                      (device_type, ip_address, user, password, secret_password, hostname, id))
            conn.commit()
            flash('Device updated successfully')
            return redirect(url_for('sl3_device'))
        
        c.execute("SELECT * FROM sl3_device WHERE id=?", (id,))
        device = c.fetchone()
        conn.close()
        
        if device:
            return render_template('edit_device_sl3.html', device=device)
        else:
            flash('Device not found')
            return redirect(url_for('sl3_device'))
    else:
        return redirect(url_for('login'))

@app.route('/devices/delete/<int:id>', methods=['GET', 'POST'])
def delete_device(id):
    if request.method == 'POST':
        conn = sqlite3.connect('device.db')
        c = conn.cursor()
        c.execute("SELECT hostname, ip_address FROM router_device WHERE id=?", (id,))
        device_info = c.fetchone()
        if device_info:
            hostname = device_info[0]
            ip_address = device_info[1]
            c.execute("DELETE FROM router_device WHERE id=?", (id,))
            conn.commit()
            conn.close()
            # Log device deletion with name and IP address
            log_event(f"Device deleted: {hostname} ({ip_address})", session.get('username'))
        return redirect(url_for('router_device'))
    return render_template('router_device.html')

@app.route('/dhcp_create', methods=['GET', 'POST'])
def dhcp_create():
    if 'logged_in' in session:
        if request.method == 'POST':
            device_ip = request.form['device_ip']
            username = request.form['username']
            password = request.form['password']
            secret_pass = request.form.get('secret_pass')
            # Process the form data here
            #...
        return render_template('dhcp_creat.html')
    else:
        return redirect(url_for('login'))


@app.route('/backup_config/<string:id>', methods=['GET'])
def backup_config(id):
    # Retrieve device details from database based on IP address
    conn = sqlite3.connect('device.db')
    cursor = conn.cursor()
    cursor.execute("SELECT ip_address, device_type, user, password, secret_password,hostname FROM router_device WHERE id=?", (id,))
    device_info = cursor.fetchone()
    conn.close()

    if not device_info:
        output = "Error: Device not found."
        return render_template('error.html', output=output)

    ip_address, device_type, user, password, secret_password,hostname = device_info  # Unpack all required fields

    # Construct the device dictionary for Netmiko
    device = {
        'device_type': device_type,
        'ip': ip_address,
        'username': user,
        'password': password,
        'port': '22',  # Default SSH port
    }

    if secret_password:
        device['secret'] = secret_password  # Add secret only if provided

    try:
        # Connect to the device and get the backup configuration
        with ConnectHandler(**device) as net_connect:
            net_connect.enable()
            output = net_connect.send_command('show running-config')
            # Generate a filename with the current date and time
            filename = f"backup_{hostname}_{ip_address}_{datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
            # Create a file object with the backup configuration
            file_obj = BytesIO()
            file_obj.write(output.encode())
            file_obj.seek(0)
            # Return the file as a downloadable attachment
            return send_file(file_obj, as_attachment=True, download_name=filename)
    except Exception as e:
        output = f"Error: {str(e)}"
        return render_template('result.html', output=output)

@app.route('/get_acl_rules', methods=['GET'])
def get_acl_rules():
    device_id = request.args.get('device_id')
    device_info = get_device_info(device_id)
    if not device_info:
        return jsonify({'status': 'error', 'message': 'Device not found'})

    device = {
        'device_type': device_info['device_type'],
        'ip': device_info['ip'],
        'username': device_info['username'],
        'password': device_info['password'],
        'port': 22,
    }

    try:
        with ConnectHandler(**device) as net_connect:
            net_connect.enable()
            output = net_connect.send_command('show ip access-lists')

        rules = parse_acl_rules(output)
        
        # Group rules by ACL name
        acl_groups = defaultdict(list)
        for rule in rules:
            acl_groups[rule['acl_name']].append(rule)

        return jsonify({'status': 'success', 'acl_groups': dict(acl_groups)})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/move_rule', methods=['POST'])
def move_rule():
    device_id = request.form['device_id']
    acl_name = request.form['acl_name']
    sequence = request.form['sequence']
    direction = request.form['direction']

    device_info = get_device_info(device_id)
    if not device_info:
        return jsonify({'status': 'error', 'message': 'Device not found'})

    device = {
        'device_type': device_info['device_type'],
        'ip': device_info['ip'],
        'username': device_info['username'],
        'password': device_info['password'],
        'port': 22,
    }

    try:
        with ConnectHandler(**device) as net_connect:
            net_connect.enable()
            
            # Get all rules for the ACL
            output = net_connect.send_command(f'show ip access-lists {acl_name}')
            rules = parse_acl_rules(output)
            
            # Find the current rule and its neighbors
            current_rule_index = next((i for i, rule in enumerate(rules) if rule['sequence'] == sequence), None)
            if current_rule_index is None:
                return jsonify({'status': 'error', 'message': 'Rule not found'})

            if direction == 'up' and current_rule_index > 0:
                swap_index = current_rule_index - 1
            elif direction == 'down' and current_rule_index < len(rules) - 1:
                swap_index = current_rule_index + 1
            else:
                return jsonify({'status': 'success', 'message': 'No change needed'})
            
            # Swap the sequences
            current_rule = rules[current_rule_index]
            swap_rule = rules[swap_index]
            
            commands = [
                f"ip access-list extended {acl_name}",
                f"no {current_rule['sequence']}",
                f"no {swap_rule['sequence']}",
                f"{swap_rule['sequence']} {current_rule['rule']}",
                f"{current_rule['sequence']} {swap_rule['rule']}"
            ]
            
            # Send commands to the device
            output = net_connect.send_config_set(commands)
            
            # Fetch updated rules
            output = net_connect.send_command(f'show ip access-lists {acl_name}')
            updated_rules = parse_acl_rules(output)
            
        return jsonify({'status': 'success', 'message': 'Rule moved successfully', 'updated_rules': updated_rules})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


def parse_acl_rules(output):
    rules = []
    current_acl = None

    for line in output.split('\n'):
        line = line.strip()
        if 'IP access list' in line:
            current_acl = line.split('list')[1].strip()
        elif line and line[0].isdigit():
            parts = line.split()
            rule = {
                'acl_name': current_acl,
                'sequence': parts[0],
                'action': parts[1],
                'protocol': parts[2],
                'source_ip': 'any',
                'destination_ip': 'any',
                'rule': ' '.join(parts[1:])  # Store the full rule
            }

            # Parse source IP
            src_index = 3
            if parts[src_index] == 'any':
                rule['source_ip'] = 'any'
                src_index += 1
            elif parts[src_index] == 'host':
                rule['source_ip'] = parts[src_index + 1]
                src_index += 2
            else:
                rule['source_ip'] = f"{parts[src_index]} {parts[src_index + 1]}"
                src_index += 2

            # Parse destination IP
            if src_index < len(parts):
                if parts[src_index] == 'any':
                    rule['destination_ip'] = 'any'
                elif parts[src_index] == 'host':
                    rule['destination_ip'] = parts[src_index + 1]
                else:
                    rule['destination_ip'] = f"{parts[src_index]} {parts[src_index + 1]}"

            rules.append(rule)

    return rules

@app.route('/router_acl_config', methods=['GET', 'POST'])
def router_acl_config():
    if 'logged_in' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect('device.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, hostname, ip_address FROM router_device")
    devices = cursor.fetchall()
    conn.close()

    if request.method == 'GET':
        return render_template('router_acl_config.html', devices=devices)
    elif request.method == 'POST':
        device_id = request.form['device_id']
        acl_name = request.form['acl_name']
        action = request.form['action']
        protocol = request.form['protocol']
        source_type = request.form['source_type']
        source_ip = request.form['source_ip']
        destination_type = request.form['destination_type']
        destination_ip = request.form['destination_ip']

        # สร้าง ACL rule
        source = 'any' if source_type == 'any' else f"host {source_ip}" if source_type == 'host' else source_ip
        destination = 'any' if destination_type == 'any' else f"host {destination_ip}" if destination_type == 'host' else destination_ip
        acl_rule = f"{action} {protocol} {source} {destination}"

        # ส่ง configuration ไปยังอุปกรณ์
        device_info = get_device_info(device_id)
        if device_info:
            device = {
                'device_type': device_info['device_type'],
                'ip': device_info['ip'],
                'username': device_info['username'],
                'password': device_info['password'],
                'port': 22,
            }
            try:
                with ConnectHandler(**device) as net_connect:
                    net_connect.enable()
                    commands = [
                        f"ip access-list extended {acl_name}",
                        acl_rule
                    ]
                    output = net_connect.send_config_set(commands)
                    return jsonify({'status': 'success', 'message': f"ACL rule added successfully: {acl_rule}"})
            except Exception as e:
                return jsonify({'status': 'error', 'message': f"Error configuring ACL: {str(e)}"})
        else:
            return jsonify({'status': 'error', 'message': "Device not found"})



@app.route('/delete_acl_rule', methods=['POST'])
def delete_acl_rule():
    device_id = request.form['device_id']
    acl_name = request.form['acl_name']
    sequence = request.form['sequence']
    
    device_info = get_device_info(device_id)
    if not device_info:
        return jsonify({'status': 'error', 'message': 'Device not found'})
    
    device = {
        'device_type': device_info['device_type'],
        'ip': device_info['ip'],
        'username': device_info['username'],
        'password': device_info['password'],
        'port': 22,
    }
    
    try:
        with ConnectHandler(**device) as net_connect:
            net_connect.enable()
            commands = [
                f"ip access-list extended {acl_name}",
                f"no {sequence}"
            ]
            # Send commands to the device
            output = net_connect.send_config_set(commands)
            
            # Fetch updated rules after deletion
            output = net_connect.send_command(f'show ip access-lists {acl_name}')
            updated_rules = parse_acl_rules(output)
            
        return jsonify({'status': 'success', 'message': 'Rule deleted successfully', 'updated_rules': updated_rules})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/delete_acl', methods=['POST'])
def delete_acl():
    device_id = request.form['device_id']
    acl_name = request.form['acl_name']
    
    device_info = get_device_info(device_id)
    if not device_info:
        return jsonify({'status': 'error', 'message': 'Device not found'})
    
    device = {
        'device_type': device_info['device_type'],
        'ip': device_info['ip'],
        'username': device_info['username'],
        'password': device_info['password'],
        'port': 22,
    }
    
    try:
        with ConnectHandler(**device) as net_connect:
            net_connect.enable()
            commands = [f"no ip access-list extended {acl_name}"]
            output = net_connect.send_config_set(commands)
            return jsonify({'status': 'success', 'message': f"ACL {acl_name} deleted"})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/show_rules', methods=['GET'])
def show_rules():
    device_id = request.args.get('device_id')
    rules = get_acl_rules(device_id)
    return jsonify({'status': 'success', 'rules': rules})
    


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8080, debug=True)






