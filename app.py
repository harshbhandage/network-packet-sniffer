from flask import Flask, render_template, jsonify, send_file,request

# Import necessary Scapy modules
from scapy.all import sniff, IP, TCP, UDP

app = Flask(__name__)

capturing = False
captured_packets = []

def packet_handler(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        packet_len = len(packet)

        # Check if it's TCP or UDP packet and get source/destination ports accordingly
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif IP in packet and TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            payload_data = packet[TCP].payload    
        else:
            src_port = None
            dst_port = None

        captured_packets.append({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "src_port": src_port,
            "dst_port": dst_port,
            "packet_len": packet_len

        })

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start_capture',methods=["POST"])
def start_capture():
    global capturing, captured_packets,interface
    interface = request.form["interface"]
    if not capturing:
        capturing = True
        captured_packets = []
        # Use iface='eth0' (or your network interface) if sniffing on a specific interface is needed.
        # You can add other filters (e.g., 'tcp', 'udp', etc.) if desired.
        sniff(iface =interface, filter="ip", prn=packet_handler, store=0)
        return jsonify({"status": "success", "message": "Packet capture started."})
    else:
        return jsonify({"status": "error", "message": "Packet capture is already running"})

@app.route('/stop_capture')
def stop_capture():
    global capturing
    capturing = False
    return jsonify({"status": "success", "message": "Packet capture stopped."})

@app.route('/captured_packets')
def get_captured_packets():
    global captured_packets
    return jsonify(captured_packets)

@app.route('/packet/<int:index>')
def get_packet_details(index):
    global captured_packets
    if 0 <= index < len(captured_packets):
        return jsonify(captured_packets[index])
    else:
        return jsonify({"status": "error", "message": "Invalid packet index."})
    
    # Define the route to download all captured packets
@app.route('/download')
def download_packets():
    file_path = 'captured_packets.txt'

    # Write all captured packets to a text file
    with open(file_path, 'w') as f:
        for packet in captured_packets:
            f.write(str(packet) + '\n')

    return send_file(file_path, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)