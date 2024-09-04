import sqlite3
from flask import Flask, jsonify, render_template, request
from flask_socketio import SocketIO, emit
from netmiko import ConnectHandler
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)

def connect_to_cisco():
    device = {
        'device_type': 'cisco_ios',
        'ip': cisco_ip,
        'username': cisco_username,
        'password': cisco_password,
    }
    return ConnectHandler(**device)

# ฟังก์ชันเชื่อมต่อกับ database
def connect_to_db():
    conn = sqlite3.connect('devices.db')
    cursor = conn.cursor()
    return conn, cursor

# ฟังก์ชันแสดงเครื่องทั้งหมด
@app.route('/show_devices', methods=['GET'])
def show_devices():
    conn, cursor = connect_to_db()
    cursor.execute('SELECT name FROM devices')
    devices = [row[0] for row in cursor.fetchall()]
    conn.close()
    return jsonify(devices)

# ฟังก์ชันแสดง rule ทั้งหมด
@app.route('/show_rules', methods=['GET'])
def show_rules():
    device_name = request.args.get('device_name')
    # Replace connect_to_cisco with the appropriate function or import it from another module
    net_connect = connect_to_cisco(device_name)
    output = net_connect.send_command('show ip access-lists')
    net_connect.disconnect()
    rules = []
    for line in output.split('\n'):
        if 'permit' in line or 'deny' in line:
            rule = {
                'rule_name': line.split()[1],
                'source_ip': line.split()[3],
                'destination_ip': line.split()[5],
                'protocol': line.split()[2],
                'action': line.split()[0]
            }
            rules.append(rule)
    return jsonify(rules)

# ฟังก์ชันส่งเครื่องทั้งหมดและ rule ไปยัง client ในแบบ real-time
@socketio.on('connect')
def connect():
    emit('devices', show_devices())
    emit('rules', show_rules())

# ฟังก์ชันรับ request จาก client และส่ง response กลับไปยัง client
@socketio.on('request_devices')
def request_devices():
    emit('devices', show_devices())

@socketio.on('request_rules')
def request_rules(device_name):
    emit('rules', show_rules(device_name=device_name))

# ฟังก์ชันแสดง select tag และตาราง rule
@app.route('/select_tag_and_rules', methods=['GET'])
def select_tag_and_rules():
    return render_template('select_tag_and_rules.html')

if __name__ == '__main__':
    socketio.run(app)