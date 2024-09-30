import sqlite3

def get_all_device_p():
    # Connect to the SQLite database
    conn = sqlite3.connect('device.db')
    cursor = conn.cursor()

    # Query to select device_p from all three tables
    query = """
        SELECT device_p FROM router_device
        UNION ALL
        SELECT device_p FROM sl2_device
        UNION ALL
        SELECT device_p FROM sl3_device;
    """

    cursor.execute(query)
    results = cursor.fetchall()  # Fetch all results

    conn.close()
    
    # Extracting the device_p values from the results
    device_p_values = [row[0] for row in results]
    
    return device_p_values

# Usage example
device_p_list = get_all_device_p()
print("Device P values from all tables:", device_p_list)