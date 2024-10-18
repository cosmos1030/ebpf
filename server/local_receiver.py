import socket
import struct
import threading
import time
import ast
import sqlite3

# The port number must match the one used in the remote script
LISTEN_PORT = 9999  # Same as LOCAL_MACHINE_PORT in remote script

# Function to handle incoming connections
def handle_client_connection(client_socket, client_address):
    try:
        while True:
            # Receive the 4-byte length header
            raw_length = recv_all(client_socket, 4)
            if not raw_length:
                break
            message_length = struct.unpack('!I', raw_length)[0]

            # Receive the actual data
            data = recv_all(client_socket, message_length)
            if not data:
                break

            # Deserialize the data
            metrics = ast.literal_eval(data.decode('utf-8'))

            # Process metrics
            process_metrics(metrics, client_address[0])
    except Exception as e:
        print(f"Error handling client connection: {e}")
    finally:
        client_socket.close()

# Helper function to ensure all data is received
def recv_all(sock, n):
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

# Function to process and display metrics
def process_metrics(metrics, client_ip):
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(metrics['timestamp']))
    cpu_usage = metrics['cpu_usage']
    mem_usage = metrics['mem_usage']
    bandwidth = metrics['bandwidth']
    packet_events = metrics['packet_events']

    print(f"[{timestamp}] Remote System Metrics from {client_ip}:")
    print(f"  CPU Usage: {cpu_usage}%")
    print(f"  Memory Usage: {mem_usage}%")
    print(f"  Bandwidth Sent: {bandwidth['bytes_sent']} bytes")
    print(f"  Bandwidth Received: {bandwidth['bytes_recv']} bytes")
    print(f"  Packet Events ({len(packet_events)} packets):")

    # Compute network metrics
    if packet_events:
        # Throughput
        total_bytes = sum(pkt['pkt_len'] for pkt in packet_events)
        duration = packet_events[-1]['timestamp'] - packet_events[0]['timestamp']
        throughput = (total_bytes * 8) / duration if duration > 0 else 0  # bps

        # Packet Delay
        inter_arrival_times = [
            packet_events[i]['timestamp'] - packet_events[i-1]['timestamp']
            for i in range(1, len(packet_events))
        ]
        average_delay = sum(inter_arrival_times) / len(inter_arrival_times) if inter_arrival_times else 0

        # Packet Loss (Not accurately measurable here)
        packet_loss = "N/A"

        print(f"  Network Metrics:")
        print(f"    Throughput: {throughput:.2f} bps")
        print(f"    Average Packet Delay: {average_delay:.6f} s")
        print(f"    Packet Loss: {packet_loss}")
    else:
        print("  No packet events received.")
        throughput = 0
        average_delay = 0
        packet_loss = "N/A"

    # Store metrics into the database
    conn = sqlite3.connect('metrics.db')
    cursor = conn.cursor()

    # Insert into metrics table
    cursor.execute('''
        INSERT INTO metrics (
            client_ip, timestamp, cpu_usage, mem_usage,
            bytes_sent, bytes_recv, throughput,
            average_delay, packet_loss
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        client_ip,
        timestamp,
        cpu_usage,
        mem_usage,
        bandwidth['bytes_sent'],
        bandwidth['bytes_recv'],
        throughput,
        average_delay,
        packet_loss
    ))
    metric_id = cursor.lastrowid

    # Insert packet events
    for pkt in packet_events:
        cursor.execute('''
            INSERT INTO packet_events (
                metric_id, packet_timestamp, pkt_len
            ) VALUES (?, ?, ?)
        ''', (
            metric_id,
            pkt['timestamp'],
            pkt['pkt_len']
        ))

    conn.commit()
    conn.close()

# Initialize the SQLite database
def init_db():
    conn = sqlite3.connect('metrics.db')
    cursor = conn.cursor()
    # Create a table for metrics
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_ip TEXT,
            timestamp TEXT,
            cpu_usage REAL,
            mem_usage REAL,
            bytes_sent INTEGER,
            bytes_recv INTEGER,
            throughput REAL,
            average_delay REAL,
            packet_loss TEXT
        )
    ''')
    # Create a table for packet events
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS packet_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            metric_id INTEGER,
            packet_timestamp REAL,
            pkt_len INTEGER,
            FOREIGN KEY(metric_id) REFERENCES metrics(id)
        )
    ''')
    conn.commit()
    conn.close()

# Start the server to listen for incoming connections
def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('', LISTEN_PORT))  # Listen on all interfaces
    server.listen(5)
    print(f"Listening on port {LISTEN_PORT}...")

    try:
        while True:
            client_sock, address = server.accept()
            print(f"Accepted connection from {address}")
            client_handler = threading.Thread(
                target=handle_client_connection,
                args=(client_sock, address),
                daemon=True
            )
            client_handler.start()
    except KeyboardInterrupt:
        print("Shutting down server.")
    finally:
        server.close()

if __name__ == "__main__":
    init_db()
    start_server()
