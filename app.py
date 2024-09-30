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



# def get_device_info(device_id):
#     conn = sqlite3.connect('device.db')
#     cursor = conn.cursor()
#     cursor.execute("SELECT device_type, ip_address, user, password FROM router_device WHERE id=?", (device_id,))
#     device_info = cursor.fetchone()
#     conn.close()
#     if device_info:
#         return {
#             'device_type': 'cisco_ios',
#             'ip': device_info[1],
#             'username': device_info[2],
#             'password': device_info[3],
#         }
#     return None

def get_device_info(device_id, device_p):
    conn = sqlite3.connect('device.db')
    cursor = conn.cursor()
    
    table_name = {
        'router_device': 'router_device',
        'sl2_device': 'sl2_device',
        'sl3_device': 'sl3_device'
    }.get(device_p)
    
    if not table_name:
        conn.close()
        return None  # Invalid device_p value
    
    cursor.execute(f"SELECT device_type, ip_address, user, password, secret_password FROM {table_name} WHERE id=?", (device_id,))
    device_info = cursor.fetchone()
    conn.close()
    
    if device_info:
        return {
            'device_type': 'cisco_ios',  # Assuming all devices use cisco_ios
            'ip': device_info[1],
            'username': device_info[2],
            'password': device_info[3],
            'secret': device_info[4]
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
            device_p = request.form['device_p']
            device_type = 'cisco_ios'
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
                "INSERT INTO router_device (device_type, ip_address, user, password, secret_password, hostname, date_add, device_p) VALUES (?,?,?,?,?,?,?,?)", 
                      (device_type, 
                       ip_address, 
                       user, 
                       password, 
                       secret_password, 
                       hostname, 
                       date_add,
                       device_p,
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
            device_p = request.form['device_type']
            device_type = 'cisco_ios'
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
                "INSERT INTO sl2_device (device_type, ip_address, user, password, secret_password, hostname, date_add, device_p) VALUES (?,?,?,?,?,?,?,?)", 
                      (device_type, 
                       ip_address, 
                       user, 
                       password, 
                       secret_password, 
                       hostname, 
                       date_add,
                       device_p,
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
            device_p = request.form['device_type']
            device_type = 'cisco_ios'
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
                "INSERT INTO sl2_device (device_type, ip_address, user, password, secret_password, hostname, date_add,  device_p) VALUES (?,?,?,?,?,?,?,?)", 

                      (device_type, 
                       ip_address, 
                       user, 
                       password, 
                       secret_password, 
                       hostname, 
                       date_add,
                       device_p,
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


@app.route('/import_backup_page')
def import_backup_page():
    if 'logged_in' in session:
        conn = sqlite3.connect('device.db')
        cursor = conn.cursor()
        cursor.execute("SELECT id, hostname, ip_address FROM router_device")
        devices = cursor.fetchall()
        conn.close()
        return render_template('/router/router_import_config.html', devices=devices)
    else:
        return redirect(url_for('login'))


ALLOWED_EXTENSIONS = {'txt', 'conf'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/import_backup', methods=['POST'])
def import_backup():
    if 'backupFile' not in request.files:
        return jsonify({'status': 'error', 'message': 'No file part'})
    
    file = request.files['backupFile']
    
    if file.filename == '':
        return jsonify({'status': 'error', 'message': 'No selected file'})
    
    if file and allowed_file(file.filename):
        file_content = file.read().decode('utf-8')
        
        device_id = request.form.get('device_id')
        device_p = request.form.get('device_p')
        device_info = get_device_info(device_id, device_p)
        
        if not device_info:
            return jsonify({'status': 'error', 'message': 'Device not found'})
        
        device = {
            'device_type': device_info['device_type'],
            'ip': device_info['ip'],
            'username': device_info['username'],
            'password': device_info['password'],
            'secret': device_info['secret'],
            'port': 22,
        }
        
        try:
            with ConnectHandler(**device) as net_connect:
                net_connect.enable()
                
                # Split the configuration into individual commands
                commands = [line.strip() for line in file_content.splitlines() if line.strip()]
                
                # Apply the configuration
                output = net_connect.send_config_set(commands)
                
                # Save the configuration
                net_connect.save_config()
                
            # Log the successful import
            log_event(f"Backup imported for device: {device_info['ip']}", session.get('username'))
            
            return jsonify({'status': 'success', 'message': 'Backup imported successfully'})
        except Exception as e:
            # Log the failed import attempt
            log_event(f"Backup import failed for device: {device_info['ip']}. Error: {str(e)}", session.get('username'))
            return jsonify({'status': 'error', 'message': str(e)})
    
    return jsonify({'status': 'error', 'message': 'Invalid file type'})

@app.route('/move_rule', methods=['POST'])
def move_rule():
    device_id = request.form['device_id']
    acl_name = request.form['acl_name']
    sequence = request.form['sequence']
    direction = request.form['direction']
    device_p = request.form['device_p']
    device_info = get_device_info(device_id, device_p)
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


@app.route('/get_acl_rules', methods=['GET'])
def get_acl_rules():
    device_id = request.args.get('device_id')
    device_p = request.args.get('device_p')
    device_info = get_device_info(device_id, device_p)
    

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
        # print(f'{rules}')
        # Group rules by ACL name
        acl_groups = defaultdict(list)
        for rule in rules:
            acl_groups[rule['acl_name']].append(rule)

        acl_applications = get_acl_applications(device_id, device_p)

        return jsonify({'status': 'success', 'acl_groups': dict(acl_groups)})
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

def get_acl_applications(device_id, device_p):
    device_info = get_device_info(device_id, device_p)  # ฟังก์ชันที่มีอยู่แล้วสำหรับดึงข้อมูลอุปกรณ์
    if not device_info:
        return []

    device = {
        'device_type': device_info['device_type'],
        'ip': device_info['ip'],
        'username': device_info['username'],
        'password': device_info['password'],
        'port': 22,
    }

    try:
        with ConnectHandler(**device) as net_connect:
            # ดึงข้อมูลการกำหนดค่าทั้งหมด
            running_config = net_connect.send_command('show running-config')

        # ใช้ฟังก์ชัน parse_acl_applications ที่มีอยู่แล้ว
        acl_applications = parse_acl_applications(running_config)
        # print("SHOW ACL NOW")
        # print(acl_applications)
        return acl_applications

    except Exception as e:
        print(f"Error in get_acl_applications: {str(e)}")
        return []

@app.route('/acl_config', methods=['GET', 'POST'])
def router_acl_config():
    if 'logged_in' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect('device.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, hostname, ip_address FROM router_device")
    devices = cursor.fetchall()
    conn.close()
    device_p = request.form.get('device_p')

    if request.method == 'GET':
        return render_template('router_acl_config.html', devices=devices)
    elif request.method == 'POST':
        device_id = request.form['device_id']
        acl_name = request.form['acl_name']
        action = request.form['action']
        protocol = request.form['protocol']
        source_type = request.form['source_type']
        source_ip = request.form['source_ip']
        source_subnet = request.form.get('source_wildcard', '')
        destination_type = request.form['destination_type']
        destination_ip = request.form['destination_ip']
        destination_subnet = request.form.get('destination_wildcard', '')
        
        # สร้าง ACL rule
        if source_type == 'any':
            source = 'any'
        elif source_type == 'host':
            source = f"host {source_ip}"
        else:
            wildcard = subnet_to_wildcard(source_subnet)
            source = f"{source_ip} {wildcard}"

        if destination_type == 'any':
            destination = 'any'
        elif destination_type == 'host':
            destination = f"host {destination_ip}"
        else:
            wildcard = subnet_to_wildcard(destination_subnet)
            destination = f"{destination_ip} {wildcard}"

        acl_rule = f"{action} {protocol} {source} {destination}"

        # ส่ง configuration ไปยังอุปกรณ์
        device_info = get_device_info(device_id, device_p)
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
                    interfaces = net_connect.send_command("show ip interface brief")
                    commands = [
                        f"ip access-list extended {acl_name}",
                        acl_rule
                    ]
                    output = net_connect.send_config_set(commands)
                    return jsonify({
                        'status': 'success',
                        'message': 'ACL rule added successfully',
                        'interfaces': interfaces
                    })
            except Exception as e:
                return jsonify({'status': 'error', 'message': f"Error configuring ACL: {str(e)}"})
        else:
            return jsonify({'status': 'error', 'message': "Device not found"})
        
        
def subnet_to_wildcard(subnet):
    subnet_octets = subnet.split('.')
    wildcard_octets = ['255' if octet == '0' else str(255 - int(octet)) for octet in subnet_octets]
    return '.'.join(wildcard_octets)


@app.route('/edit_acl_rule', methods=['POST'])
def edit_acl_rule():
    device_id = request.form['device_id']
    acl_name = request.form['acl_name']
    sequence = request.form['sequence']
    action = request.form['action']
    protocol = request.form['protocol']
    source_type = request.form['source_type']
    source_ip = request.form['source_ip']
    source_wildcard = request.form.get('source_wildcard', '')
    destination_type = request.form['destination_type']
    destination_ip = request.form['destination_ip']
    destination_wildcard = request.form.get('destination_wildcard', '')
    device_p = request.form.get('device_p')
    device_info = get_device_info(device_id, device_p)
    if not device_info:
        return jsonify({'status': 'error', 'message': 'Device not found'})
    
    device = {
        'device_type': device_info['device_type'],
        'ip': device_info['ip'],
        'username': device_info['username'],
        'password': device_info['password'],
        'port': 22,
    }
    
    # Construct source and destination parts of the ACL rule
    if source_type == 'any':
        source = 'any'
    elif source_type == 'host':
        source = source_ip  # 'host' prefix is already added in frontend
    else:
        wildcard = subnet_to_wildcard(source_wildcard)
        source = f"{source_ip} {wildcard}"

    if destination_type == 'any':
        destination = 'any'
    elif destination_type == 'host':
        destination = destination_ip  # 'host' prefix is already added in frontend
    else:
        wildcard = subnet_to_wildcard(destination_wildcard)
        destination = f"{destination_ip} {wildcard}"

        
    try:
        with ConnectHandler(**device) as net_connect:
            net_connect.enable()
            
            # Check if the rule exists
            show_acl = net_connect.send_command(f'show ip access-list {acl_name}')
            # if f"sequence {sequence}" not in show_acl:
            #     return jsonify({'status': 'error', 'message': f'Rule with sequence {sequence} not found in ACL {acl_name}'})
            
            # Construct the new rule
            new_rule = f"{sequence} {action} {protocol} {source} {destination}"
            print(f"New rule to be added: {new_rule}")
            commands = [
                f"ip access-list extended {acl_name}",
                f"no {sequence}",  # Remove the old rule
                new_rule  # Add the new rule
            ]
            output = net_connect.send_config_set(commands)
            
            # Verify if the rule was added successfully
            show_acl_after = net_connect.send_command(f'show ip access-list {acl_name}')
            if new_rule not in show_acl_after:
                return jsonify({'status': 'error', 'message': 'Failed to edit the rule. Please check the device configuration.'})
            
            # Fetch updated rules
            updated_rules = parse_acl_rules(show_acl_after)
            
        return jsonify({'status': 'success', 'message': 'Rule edited successfully', 'updated_rules': updated_rules})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})    
    


@app.route('/delete_acl_rule', methods=['POST'])
def delete_acl_rule():
    device_id = request.form['device_id']
    acl_name = request.form['acl_name']
    sequence = request.form['sequence']
    device_p = request.form.get('device_p')
    
    device_info = get_device_info(device_id, device_p)
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


@app.route('/get_interfaces', methods=['GET'])
def get_interfaces():
    device_id = request.args.get('device_id')
    device_p = request.args.get('device_p')
    device_info = get_device_info(device_id, device_p)
    
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
            output = net_connect.send_command('show ip interface brief')
            config = net_connect.send_command('show running-config')
            acl_output = net_connect.send_command('show ip access-lists')

        # print("Raw interfaces output:")
        # print(output)

        # print("Raw ACL output:")
        # print(acl_output)

        interfaces = parse_interfaces(output)
        acl_applications = parse_acl_applications(config)
        acl_rules = parse_acl_rules(acl_output)

        return jsonify({
            'status': 'success',
            'interfaces': interfaces,
            'acl_applications': acl_applications,
            'acl_rules': acl_rules
        })
    except Exception as e:
        print(f"Error in get_interfaces: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)})

def parse_interfaces(output):
    interfaces = []
    lines = output.strip().split('\n')
    
    # Find the header line
    header_index = next((i for i, line in enumerate(lines) if 'Interface' in line), 0)
    
    for line in lines[header_index + 1:]:
        parts = line.split()
        if len(parts) >= 2:
            interface = {
                'name': parts[0],
                'ip_address': parts[1] if parts[1] != 'unassigned' else '',
                'status': parts[-1] if len(parts) > 4 else 'unknown'
            }
            interfaces.append(interface)
    
    return interfaces

def parse_acl_applications(config):
    acl_applications = []
    current_interface = None

    for line in config.split('\n'):
        line = line.strip()
        # print(f"Processing line: {line}")  # Print each line for debugging
        if line.startswith('interface'):
            current_interface = line.split()[1]
            # print(f"Current interface: {current_interface}")
        elif current_interface and 'access-group' in line:
            parts = line.split()
            if len(parts) >= 4 and parts[0] == 'ip':
                parts = parts[1:]  # Remove 'ip' if present
            if len(parts) >= 3 and parts[0] == 'access-group':
                acl_application = {
                    'interface': current_interface,
                    'acl_name': parts[1],
                    'direction': parts[2]
                }
                acl_applications.append(acl_application)
                # print(f"ACL application found: {acl_application}")
        elif line == '!':
            if current_interface:
                # print(f"End of interface {current_interface} configuration")
                current_interface = None

    # print(f"Total ACL applications found: {len(acl_applications)}")
    return acl_applications
@app.route('/apply_acl', methods=['POST'])
def apply_acl():
    device_id = request.form['device_id']
    interface = request.form['interface']
    acl_name = request.form['acl_name']
    direction = request.form['direction']
    device_p = request.form.get('device_p')
    device_info = get_device_info(device_id, device_p)
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
                f"interface {interface}",
                f"ip access-group {acl_name} {direction}"
            ]
            output = net_connect.send_config_set(commands)
            
            # Verify the application
            running_config = net_connect.send_command('show running-config')
            acl_applications = parse_acl_applications(running_config)
            
        return jsonify({
            'status': 'success',
            'message': f'ACL {acl_name} applied to {interface} in {direction} direction',
            'acl_applications': acl_applications
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/delete_applied_acl', methods=['POST'])
def delete_applied_acl():
    device_id = request.form.get('device_id')
    interface = request.form.get('interface')
    acl_name = request.form.get('acl_name')
    direction = request.form.get('direction')
    device_p = request.form.get('device_p')

    # Fetch device details from the database
    device_info = get_device_info(device_id, device_p)
    if not device_info:
        return jsonify({'status': 'error', 'message': 'Device not found'}), 404

    device = {
        'device_type': device_info['device_type'],
        'ip': device_info['ip'],
        'username': device_info['username'],
        'password': device_info['password'],
        'secret': device_info.get('secret'),  # Add this if your devices use enable secret
        'port': 22,  # Change if your SSH port is different
    }

    try:
        with ConnectHandler(**device) as net_connect:
            net_connect.enable()  # Enter enable mode if required

            # Commands to remove the ACL from the interface
            commands = [
                f'interface {interface}',
                f'no ip access-group {acl_name} {direction}'
            ]

            # Send commands to the device
            output = net_connect.send_config_set(commands)

            # Check if the command was successful
            if "Invalid input detected" in output or "% " in output:
                return jsonify({
                    'status': 'error',
                    'message': f'Error removing ACL: {output}'
                }), 400

            # Save the configuration
            net_connect.save_config()

            return jsonify({
                'status': 'success',
                'message': f'ACL {acl_name} removed from {interface} ({direction})'
            })

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'An error occurred while removing the ACL: {str(e)}'
        }), 500


#################### DHCP ###########################################################

@app.route('/get_devices')
def get_devices():
    conn = sqlite3.connect('device.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, hostname, ip_address FROM router_device")
    devices = [{'id': row[0], 'hostname': row[1], 'ip_address': row[2]} for row in cursor.fetchall()]
    conn.close()
    return jsonify({'devices': devices})

@app.route('/dhcp/create',methods=['GET','POST'])
def dhcp_pool():
    if 'logged_in' in session:
        return render_template('dhcp_creat.html')
    
    conn = sqlite3.connect('device.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, hostname, ip_address FROM router_device")
    devices = cursor.fetchall()
    conn.close()
    # device_p = 'router_device'
    
    if request.method == 'GET':
        return render_template('dhcp_creat.html', devices=devices)
    else:
        return redirect(url_for('login'))


@app.route('/create_dhcp_pool', methods=['POST'])
def create_dhcp_pool():
    device_id = request.form['device_id']
    pool_name = request.form['poolName']
    network_address = request.form['networkAddress']
    subnet_mask = request.form['subnetMask']
    default_router = request.form['defaultRouter']
    dns_server = request.form['dnsServer']
    domain_name = request.form['domainName']
    lease_time = request.form['leaseTime']
    excluded_addresses = request.form.getlist('excludedAddresses[]')  # Change this line  # Assuming this is sent as an array
    device_p = request.form.get('device_p')

    device_info = get_device_info(device_id, device_p)
    if not device_info:
        return jsonify({'status': 'error', 'message': 'Device not found'})

    device = {
        'device_type': device_info['device_type'],
        'ip': device_info['ip'],
        'username': device_info['username'],
        'password': device_info['password'],
        'secret': device_info['secret'],
        'port': 22,
    }

    try:
        with ConnectHandler(**device) as net_connect:
            net_connect.enable()
            commands = [
                f'ip dhcp pool {pool_name}',
                f'network {network_address} {subnet_mask}',
                f'default-router {default_router}',
                f'dns-server {dns_server}',
                f'domain-name {domain_name}',
                f'lease {lease_time}'
            ]
            if excluded_addresses:
                for address in excluded_addresses:
                    if '-' in address:  # Range of addresses
                        start, end = address.split('-')
                        commands.append(f'ip dhcp excluded-address {start.strip()} {end.strip()}')
                    else:  # Single address
                        commands.append(f'ip dhcp excluded-address {address.strip()}')

            output = net_connect.send_config_set(commands)
            net_connect.save_config()
        return jsonify({'status': 'success', 'message': 'DHCP pool created successfully'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/get_dhcp_pools', methods=['GET'])
def get_dhcp_pools():
    device_id = request.args.get('device_id')
    device_p = request.args.get('device_p')
    device_info = get_device_info(device_id, device_p)
    if not device_info:
        return jsonify({'status': 'error', 'message': 'Device not found'})

    device = {
        'device_type': device_info['device_type'],
        'ip': device_info['ip'],
        'username': device_info['username'],
        'password': device_info['password'],
        'secret': device_info['secret'],
        'port': 22,
    }

    try:
        with ConnectHandler(**device) as net_connect:
            net_connect.enable()
            output = net_connect.send_command('show running-config | section ip dhcp pool')
            excluded_output = net_connect.send_command('show running-config | section ip dhcp excluded-address')
        pools = parse_dhcp_pools(output)
        excluded = parse_excluded_addresses(excluded_output)
        print(pools)
        print(excluded_output)
        print(excluded)
        for pool in pools:
            pool['excluded_addresses'] = [
                f"{item['start']} - {item['end']}" if 'start' in item else item['address']
                for item in excluded
            ]
        
        return jsonify({'status': 'success', 'pools': pools, 'excluded': excluded})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/delete_dhcp_pool', methods=['POST'])
def delete_dhcp_pool():
    data = request.json
    device_id = data['device_id']
    pool_name = data['pool_name']

    device_info = get_device_info(device_id, 'router_device')
    if not device_info:
        return jsonify({'status': 'error', 'message': 'Device not found'})

    device = {
        'device_type': device_info['device_type'],
        'ip': device_info['ip'],
        'username': device_info['username'],
        'password': device_info['password'],
        'secret': device_info['secret'],
        'port': 22,
    }

    try:
        with ConnectHandler(**device) as net_connect:
            net_connect.enable()
            commands = [f'no ip dhcp pool {pool_name}']
            output = net_connect.send_config_set(commands)
            net_connect.save_config()
        return jsonify({'status': 'success', 'message': 'DHCP pool deleted successfully'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

def parse_dhcp_pools(config_output):
    pools = []
    current_pool = None
    for line in config_output.split('\n'):
        line = line.strip()
        if line.startswith('ip dhcp pool'):
            if current_pool:
                pools.append(current_pool)
            current_pool = {'name': line.split()[-1], 'network': '', 'subnet': '', 'default_router': '', 'dns_server': '', 'domain_name': '', 'lease_time': ''}
        elif current_pool:
            if line.startswith('network'):
                parts = line.split()
                current_pool['network'] = parts[1]
                current_pool['subnet'] = parts[2]
            elif line.startswith('default-router'):
                current_pool['default_router'] = line.split()[-1]
            elif line.startswith('dns-server'):
                current_pool['dns_server'] = line.split()[-1]
            elif line.startswith('domain-name'):
                current_pool['domain_name'] = line.split()[-1]
            elif line.startswith('lease'):
                current_pool['lease_time'] = ' '.join(line.split()[1:])
    if current_pool:
        pools.append(current_pool)
    return pools

def parse_excluded_addresses(excluded_output):
    excluded = []
    for line in excluded_output.split('\n'):
        line = line.strip()
        if line.startswith('ip dhcp excluded-address'):
            parts = line.split()[3:]  # Skip 'ip dhcp excluded-address'
            if len(parts) == 2:
                excluded.append({'start': parts[0], 'end': parts[1]})
            elif len(parts) == 1:
                excluded.append({'address': parts[0]})
    return excluded

@app.route('/edit_dhcp_pool', methods=['POST'])
def edit_dhcp_pool():
    device_id = request.form['device_id']
    old_pool_name = request.form.get('old_pool_name')  # Use .get() method
    pool_name = request.form['poolName']
    network_address = request.form['networkAddress']
    subnet_mask = request.form['subnetMask']
    default_router = request.form['defaultRouter']
    dns_server = request.form['dnsServer']
    domain_name = request.form['domainName']
    lease_time = request.form['leaseTime']
    excluded_addresses = request.form.getlist('excludedAddresses[]')
    device_p = request.form.get('device_p', 'router_device')

    device_info = get_device_info(device_id, device_p)
    if not device_info:
        return jsonify({'status': 'error', 'message': 'Device not found'})

    device = {
        'device_type': device_info['device_type'],
        'ip': device_info['ip'],
        'username': device_info['username'],
        'password': device_info['password'],
        'secret': device_info['secret'],
        'port': 22,
    }

    try:
        with ConnectHandler(**device) as net_connect:
            net_connect.enable()
            
            # Remove the old DHCP pool
            commands = [f'no ip dhcp pool {old_pool_name}']
            net_connect.send_config_set(commands)

            # Create the new DHCP pool
            commands = [
                f'ip dhcp pool {pool_name}',
                f'network {network_address} {subnet_mask}',
                f'default-router {default_router}',
                f'dns-server {dns_server}',
                f'domain-name {domain_name}',
                f'lease {lease_time}'
            ]

            if excluded_addresses:
                no_ip_dhcp_excluded_address = net_connect.send_command('show run | include ip dhcp excluded-address')
                for line in no_ip_dhcp_excluded_address.splitlines():
                    if line.strip().startswith('ip dhcp excluded-address'):
                        commands.append(f'no {line.strip()}')
                for address in excluded_addresses:
                    if '-' in address:  # Range of addresses
                        start, end = address.split('-')
                        commands.append(f'ip dhcp excluded-address {start.strip()} {end.strip()}')
                    else:  # Single address
                        commands.append(f'ip dhcp excluded-address {address.strip()}')

            output = net_connect.send_config_set(commands)
            net_connect.save_config()

            # Verify the changes
            new_config = net_connect.send_command('show run | section ip dhcp pool')
            new_excluded = net_connect.send_command('show run | include ip dhcp excluded-address')
            
            updated_pool = parse_dhcp_pools(new_config)
            updated_excluded = parse_excluded_addresses(new_excluded)

        return jsonify({
            'status': 'success', 
            'message': 'DHCP pool updated successfully',
            'updated_pool': updated_pool,
            'updated_excluded': updated_excluded
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


@app.route('/delete_excluded_address', methods=['POST'])
def delete_excluded_address():
    data = request.json
    device_id = data['device_id']
    excluded_address = data['excluded_address']
    device_p = data.get('device_p', 'router_device')

    device_info = get_device_info(device_id, device_p)
    if not device_info:
        return jsonify({'status': 'error', 'message': 'Device not found'})

    device = {
        'device_type': device_info['device_type'],
        'ip': device_info['ip'],
        'username': device_info['username'],
        'password': device_info['password'],
        'secret': device_info['secret'],
        'port': 22,
    }

    try:
        with ConnectHandler(**device) as net_connect:
            net_connect.enable()
            if ' - ' in excluded_address:
                start, end = excluded_address.split(' - ')
                command = f'no ip dhcp excluded-address {start.strip()} {end.strip()}'
            else:
                command = f'no ip dhcp excluded-address {excluded_address}'
            output = net_connect.send_config_set([command])
            net_connect.save_config()

        return jsonify({'status': 'success', 'message': 'Excluded address deleted successfully'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8080, debug=True)






