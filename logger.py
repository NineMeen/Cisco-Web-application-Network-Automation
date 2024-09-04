import sqlite3
import datetime

def log_event(event, username):
    conn = sqlite3.connect('user.db')
    c = conn.cursor()
    now = datetime.datetime.now()
    timestamp = now.strftime("%d-%m-%Y %H:%M:%S")
    c.execute("INSERT INTO log (event, username, timestamp) VALUES (?, ?, ?)", (event, username, timestamp))
    conn.commit()
    conn.close()