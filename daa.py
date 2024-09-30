import sqlite3

def get_device_info(device_id):
    # Connect to the SQLite database
    conn = sqlite3.connect('device.db')
    cursor = conn.cursor()

    # Query all tables for device_type
    device_p = None
    for table in ['router_device', 'sl2_device', 'sl3_device']:
        cursor.execute(f"SELECT device_p FROM {table} WHERE id=?", (device_id,))
        result = cursor.fetchone()
        if result:
            device_p = result[0]
            break

    if device_p is None:
        print(f"Device ID {device_id} not found in any table")
        conn.close()
        return None

    # Query the corresponding table based on device_type
    if device_p == 'router_device':
        table = 'router_device'
    elif device_p == 'sl2_device':
        table = 'sl2_device'
    elif device_p == 'sl3_device':
        table = 'sl3_device'
    else:
        print(f"Unknown device type: {device_p}")
        conn.close()
        return None

    cursor.execute(f"SELECT device_type, ip_address, user, password, secret_password FROM {table} WHERE id=?", (device_id,))
    results = cursor.fetchone()  # Fetch one result
    conn.close()

    if results:
        return {
            'device_type': results[0],
            'ip': results[1],
            'username': results[2],
            'password': results[3],
        }
    return None

# Example usage:
device_id = 1
device_info = get_device_info(device_id)
print(device_info)