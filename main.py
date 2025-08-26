import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QTextEdit, QPushButton, QLabel, QTableWidget, QTableWidgetItem, QMessageBox, QHBoxLayout
from PyQt5.QtCore import Qt

def convert_string(input_str):
    # Remove pipes and concatenate the string
    try:
        return input_str.replace('|', '')
    except Exception as e:
        print(f"Error in convert_string: {e}")
        return ""

def hex_to_binary(hex_str):
    # Convert hexadecimal string to binary, processing two chars (one byte) at a time
    binary = ''
    try:
        for i in range(0, len(hex_str), 2):
            byte = hex_str[i:i+2]
            binary += format(int(byte, 16), '08b')
        return binary
    except ValueError as e:
        print(f"Error in hex_to_binary: {e}")
        return "Invalid hex string"

def segment_headers(datagram_str):
    print(f"Processing datagram: {datagram_str[:50]}...")  # Debug: Print first 50 chars
    clean_datagram = convert_string(datagram_str)
    if not clean_datagram:
        print("Error: Empty or invalid datagram after conversion")
        return None
    if len(clean_datagram) < 108:
        print(f"Error: Datagram too short, length: {len(clean_datagram)}")
        return None
    clean_header = clean_datagram[:108]
    
    if not all(c in '0123456789abcdefABCDEF' for c in clean_header):
        print("Error: Invalid hex characters in datagram")
        return None
    
    ethernet_header = clean_header[:28]
    ipv4_header = clean_header[28:68]
    tcp_header = clean_header[68:108]
    
    headers = {
        'Ethernet': {
            'hex': ethernet_header,
            'binary': hex_to_binary(ethernet_header),
            'fields': {
                'Destination MAC': ethernet_header[:12],
                'Source MAC': ethernet_header[12:24],
                'Type': ethernet_header[24:28]
            }
        },
        'IP': {
            'hex': ipv4_header,
            'binary': hex_to_binary(ipv4_header),
            'fields': {
                'Version': hex_to_binary(ipv4_header[:1])[0:4] if hex_to_binary(ipv4_header[:1]) != "Invalid hex string" else "Error",
                'IHL': hex_to_binary(ipv4_header[:1])[4:8] if hex_to_binary(ipv4_header[:1]) != "Invalid hex string" else "Error",
                'DSCP': hex_to_binary(ipv4_header[2:4])[0:6] if hex_to_binary(ipv4_header[2:4]) != "Invalid hex string" else "Error",
                'ECN': hex_to_binary(ipv4_header[2:4])[6:8] if hex_to_binary(ipv4_header[2:4]) != "Invalid hex string" else "Error",
                'Total Length': ipv4_header[4:8],
                'Identification': ipv4_header[8:12],
                'Flags': hex_to_binary(ipv4_header[12:14])[0:3] if hex_to_binary(ipv4_header[12:14]) != "Invalid hex string" else "Error",
                'Fragment Offset': hex_to_binary(ipv4_header[12:14])[3:16] if hex_to_binary(ipv4_header[12:14]) != "Invalid hex string" else "Error",
                'TTL': ipv4_header[16:18],
                'Protocol': ipv4_header[18:20],
                'Header Checksum': ipv4_header[20:24],
                'Source IP': '.'.join(str(int(ipv4_header[i:i+2], 16)) for i in range(24, 32, 2)) if all(c in '0123456789abcdefABCDEF' for c in ipv4_header[24:32]) else "Error",
                'Destination IP': '.'.join(str(int(ipv4_header[i:i+2], 16)) for i in range(32, 40, 2)) if all(c in '0123456789abcdefABCDEF' for c in ipv4_header[32:40]) else "Error"
            }
        },
        'TCP': {
            'hex': tcp_header,
            'binary': hex_to_binary(tcp_header),
            'fields': {
                'Source Port': str(int(tcp_header[:4], 16)) if all(c in '0123456789abcdefABCDEF' for c in tcp_header[:4]) else "Error",
                'Destination Port': str(int(tcp_header[4:8], 16)) if all(c in '0123456789abcdefABCDEF' for c in tcp_header[4:8]) else "Error",
                'Sequence Number': str(int(tcp_header[8:16], 16)) if all(c in '0123456789abcdefABCDEF' for c in tcp_header[8:16]) else "Error",
                'Acknowledgment Number': str(int(tcp_header[16:24], 16)) if all(c in '0123456789abcdefABCDEF' for c in tcp_header[16:24]) else "Error",
                'Data Offset': hex_to_binary(tcp_header[24:26])[0:4] if hex_to_binary(tcp_header[24:26]) != "Invalid hex string" else "Error",
                'Reserved': hex_to_binary(tcp_header[24:26])[4:7] if hex_to_binary(tcp_header[24:26]) != "Invalid hex string" else "Error",
                'Flags': hex_to_binary(tcp_header[26:28])[0:8] if hex_to_binary(tcp_header[26:28]) != "Invalid hex string" else "Error",
                'Window Size': str(int(tcp_header[28:32], 16)) if all(c in '0123456789abcdefABCDEF' for c in tcp_header[28:32]) else "Error",
                'Checksum': tcp_header[32:36],
                'Urgent Pointer': tcp_header[36:40]
            },
            'tcp_flags': {
                'CWR': hex_to_binary(tcp_header[26:28])[0] if hex_to_binary(tcp_header[26:28]) != "Invalid hex string" else "Error",
                'ECE': hex_to_binary(tcp_header[26:28])[1] if hex_to_binary(tcp_header[26:28]) != "Invalid hex string" else "Error",
                'URG': hex_to_binary(tcp_header[26:28])[2] if hex_to_binary(tcp_header[26:28]) != "Invalid hex string" else "Error",
                'ACK': hex_to_binary(tcp_header[26:28])[3] if hex_to_binary(tcp_header[26:28]) != "Invalid hex string" else "Error",
                'PSH': hex_to_binary(tcp_header[26:28])[4] if hex_to_binary(tcp_header[26:28]) != "Invalid hex string" else "Error",
                'RST': hex_to_binary(tcp_header[26:28])[5] if hex_to_binary(tcp_header[26:28]) != "Invalid hex string" else "Error",
                'SYN': hex_to_binary(tcp_header[26:28])[6] if hex_to_binary(tcp_header[26:28]) != "Invalid hex string" else "Error",
                'FIN': hex_to_binary(tcp_header[26:28])[7] if hex_to_binary(tcp_header[26:28]) != "Invalid hex string" else "Error"
            }
        }
    }
    print(f"Parsed headers: Ethernet={headers['Ethernet']['hex']}, IP={headers['IP']['hex']}, TCP={headers['TCP']['hex']}")  # Debug
    return headers

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Header Segmenter - Industrial Tool")
        self.setGeometry(100, 100, 1000, 800)
        
        self.is_dark_mode = False
        
        # Main layout
        main_widget = QWidget()
        main_layout = QVBoxLayout()
        
        # Theme button at top-right
        header_layout = QHBoxLayout()
        self.theme_button = QPushButton("Dark Mode")
        self.theme_button.setFixedWidth(120)
        header_layout.addStretch()
        header_layout.addWidget(self.theme_button)
        main_layout.addLayout(header_layout)
        
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)
        
        # Tab 1: Datagram Input
        input_tab = QWidget()
        input_layout = QVBoxLayout()
        self.input_text = QTextEdit()
        self.input_text.setPlaceholderText("Enter pipe-separated hex datagram (e.g., |b0|a4|60|...)")
        self.status_label = QLabel("Enter a datagram to process.")
        self.process_button = QPushButton("Process Datagram")
        self.process_button.clicked.connect(self.process_input)
        self.theme_button.clicked.connect(self.toggle_theme)
        input_layout.addWidget(QLabel("Datagram Input (Hex, Pipe-Separated):"))
        input_layout.addWidget(self.input_text)
        input_layout.addWidget(self.process_button)
        input_layout.addWidget(self.status_label)
        input_tab.setLayout(input_layout)
        self.tab_widget.addTab(input_tab, "Datagram Input")
        
        # Tab 2: Ethernet
        eth_tab = QWidget()
        eth_layout = QVBoxLayout()
        self.eth_table = QTableWidget()
        self.eth_table.setRowCount(3)
        self.eth_table.setColumnCount(2)
        self.eth_table.setHorizontalHeaderLabels(['Field', 'Value'])
        self.eth_table.setVerticalHeaderLabels(['Destination MAC', 'Source MAC', 'Type'])
        self.eth_table.horizontalHeader().setStretchLastSection(True)
        self.eth_table.setAlternatingRowColors(True)
        eth_layout.addWidget(QLabel("Ethernet Header Fields:"))
        eth_layout.addWidget(self.eth_table)
        eth_tab.setLayout(eth_layout)
        self.tab_widget.addTab(eth_tab, "Ethernet")
        
        # Tab 3: IP
        ip_tab = QWidget()
        ip_layout = QVBoxLayout()
        self.ip_table = QTableWidget()
        self.ip_table.setRowCount(13)
        self.ip_table.setColumnCount(2)
        self.ip_table.setHorizontalHeaderLabels(['Field', 'Value'])
        self.ip_table.setVerticalHeaderLabels(['Version', 'IHL', 'DSCP', 'ECN', 'Total Length', 'Identification', 'Flags', 'Fragment Offset', 'TTL', 'Protocol', 'Header Checksum', 'Source IP', 'Destination IP'])
        self.ip_table.horizontalHeader().setStretchLastSection(True)
        self.ip_table.setAlternatingRowColors(True)
        ip_layout.addWidget(QLabel("IP Header Fields:"))
        ip_layout.addWidget(self.ip_table)
        ip_tab.setLayout(ip_layout)
        self.tab_widget.addTab(ip_tab, "IP")
        
        # Tab 4: TCP
        tcp_tab = QWidget()
        tcp_layout = QVBoxLayout()
        self.tcp_table = QTableWidget()
        self.tcp_table.setRowCount(10)
        self.tcp_table.setColumnCount(2)
        self.tcp_table.setHorizontalHeaderLabels(['Field', 'Value'])
        self.tcp_table.setVerticalHeaderLabels(['Source Port', 'Destination Port', 'Sequence Number', 'Acknowledgment Number', 'Data Offset', 'Reserved', 'Flags', 'Window Size', 'Checksum', 'Urgent Pointer'])
        self.tcp_table.horizontalHeader().setStretchLastSection(True)
        self.tcp_table.setAlternatingRowColors(True)
        tcp_layout.addWidget(QLabel("TCP Header Fields:"))
        tcp_layout.addWidget(self.tcp_table)
        tcp_tab.setLayout(tcp_layout)
        self.tab_widget.addTab(tcp_tab, "TCP")
        
        # Tab 5: TCP Flags
        flags_tab = QWidget()
        flags_layout = QVBoxLayout()
        self.flags_table = QTableWidget()
        self.flags_table.setRowCount(8)
        self.flags_table.setColumnCount(2)
        self.flags_table.setHorizontalHeaderLabels(['Flag', 'Value'])
        self.flags_table.setVerticalHeaderLabels(['CWR', 'ECE', 'URG', 'ACK', 'PSH', 'RST', 'SYN', 'FIN'])
        self.flags_table.horizontalHeader().setStretchLastSection(True)
        self.flags_table.setAlternatingRowColors(True)
        flags_layout.addWidget(QLabel("TCP Flags:"))
        flags_layout.addWidget(self.flags_table)
        flags_tab.setLayout(flags_layout)
        self.tab_widget.addTab(flags_tab, "TCP Flags")
        
        self.apply_theme()

    def apply_theme(self):
        if self.is_dark_mode:
            stylesheet = """
                QMainWindow, QWidget {
                    background-color: #1e1e1e;
                    color: #e0e0e0;
                }
                QTabWidget::pane {
                    border: 1px solid #3a3a3a;
                    background-color: #252525;
                }
                QTabBar::tab {
                    background-color: #2d2d2d;
                    color: #e0e0e0;
                    padding: 10px 20px;
                    border: 1px solid #3a3a3a;
                    border-bottom: none;
                    font-family: Roboto, Arial, sans-serif;
                    font-size: 16px;
                    font-weight: bold;
                }
                QTabBar::tab:selected {
                    background-color: #005f99;
                    color: #ffffff;
                    border-bottom: 2px solid #007acc;
                }
                QTextEdit {
                    background-color: #2d2d2d;
                    color: #e0e0e0;
                    border: 1px solid #3a3a3a;
                    font-family: 'Courier New', monospace;
                    font-size: 16px;
                    padding: 8px;
                    border-radius: 4px;
                }
                QTableWidget {
                    background-color: #2d2d2d;
                    color: #e0e0e0;
                    border: 1px solid #3a3a3a;
                    font-family: 'Courier New', monospace;
                    font-size: 16px;
                    gridline-color: #3a3a3a;
                }
                QTableWidget::item {
                    padding: 8px;
                }
                QTableWidget::item:alternate {
                    background-color: #333333;
                }
                QHeaderView::section {
                    background-color: #2d2d2d;
                    color: #e0e0e0;
                    padding: 8px;
                    border: 1px solid #3a3a3a;
                    font-family: Roboto, Arial, sans-serif;
                    font-size: 16px;
                    font-weight: bold;
                }
                QPushButton {
                    background-color: #005f99;
                    color: #ffffff;
                    border: 1px solid #004c7a;
                    padding: 8px 16px;
                    border-radius: 4px;
                    font-family: Roboto, Arial, sans-serif;
                    font-size: 16px;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background-color: #007acc;
                }
                QLabel {
                    font-family: Roboto, Arial, sans-serif;
                    font-size: 16px;
                    color: #e0e0e0;
                    font-weight: bold;
                }
            """
            self.theme_button.setText("Light Mode")
        else:
            stylesheet = """
                QMainWindow, QWidget {
                    background-color: #e8ecef;
                    color: #2d3436;
                }
                QTabWidget::pane {
                    border: 1px solid #b0b8bf;
                    background-color: #ffffff;
                }
                QTabBar::tab {
                    background-color: #d1d7db;
                    color: #2d3436;
                    padding: 10px 20px;
                    border: 1px solid #b0b8bf;
                    border-bottom: none;
                    font-family: Roboto, Arial, sans-serif;
                    font-size: 16px;
                    font-weight: bold;
                }
                QTabBar::tab:selected {
                    background-color: #007acc;
                    color: #ffffff;
                    border-bottom: 2px solid #005f99;
                }
                QTextEdit {
                    background-color: #ffffff;
                    color: #2d3436;
                    border: 1px solid #b0b8bf;
                    font-family: 'Courier New', monospace;
                    font-size: 16px;
                    padding: 8px;
                    border-radius: 4px;
                }
                QTableWidget {
                    background-color: #ffffff;
                    color: #2d3436;
                    border: 1px solid #b0b8bf;
                    font-family: 'Courier New', monospace;
                    font-size: 16px;
                    gridline-color: #b0b8bf;
                }
                QTableWidget::item {
                    padding: 8px;
                }
                QTableWidget::item:alternate {
                    background-color: #f1f3f5;
                }
                QHeaderView::section {
                    background-color: #d1d7db;
                    color: #2d3436;
                    padding: 8px;
                    border: 1px solid #b0b8bf;
                    font-family: Roboto, Arial, sans-serif;
                    font-size: 16px;
                    font-weight: bold;
                }
                QPushButton {
                    background-color: #007acc;
                    color: #ffffff;
                    border: 1px solid #005f99;
                    padding: 8px 16px;
                    border-radius: 4px;
                    font-family: Roboto, Arial, sans-serif;
                    font-size: 16px;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background-color: #0090e6;
                }
                QLabel {
                    font-family: Roboto, Arial, sans-serif;
                    font-size: 16px;
                    color: #2d3436;
                    font-weight: bold;
                }
            """
            self.theme_button.setText("Dark Mode")
        self.setStyleSheet(stylesheet)

    def toggle_theme(self):
        self.is_dark_mode = not self.is_dark_mode
        self.apply_theme()

    def process_input(self):
        datagram_str = self.input_text.toPlainText().strip()
        if not datagram_str:
            self.status_label.setText("Error: No datagram entered.")
            QMessageBox.critical(self, "Error", "No datagram entered.")
            return
        
        headers = segment_headers(datagram_str)
        if headers is None:
            self.status_label.setText("Error: Invalid datagram (too short or contains invalid hex characters).")
            QMessageBox.critical(self, "Error", "Invalid datagram. Ensure it has at least 54 bytes (108 hex chars) and valid hex characters.")
            return
        
        self.status_label.setText("Datagram processed successfully.")
        
        try:
            # Clear tables before updating
            for table in [self.eth_table, self.ip_table, self.tcp_table, self.flags_table]:
                for row in range(table.rowCount()):
                    for col in range(table.columnCount()):
                        table.setItem(row, col, None)
            
            # Update Ethernet table
            eth_fields = headers['Ethernet']['fields']
            for row, key in enumerate(['Destination MAC', 'Source MAC', 'Type']):
                self.eth_table.setItem(row, 0, QTableWidgetItem(key))
                self.eth_table.setItem(row, 1, QTableWidgetItem(eth_fields[key]))
            
            # Update IP table
            ip_fields = headers['IP']['fields']
            for row, key in enumerate(['Version', 'IHL', 'DSCP', 'ECN', 'Total Length', 'Identification', 'Flags', 'Fragment Offset', 'TTL', 'Protocol', 'Header Checksum', 'Source IP', 'Destination IP']):
                self.ip_table.setItem(row, 0, QTableWidgetItem(key))
                self.ip_table.setItem(row, 1, QTableWidgetItem(ip_fields[key]))
            
            # Update TCP table
            tcp_fields = headers['TCP']['fields']
            for row, key in enumerate(['Source Port', 'Destination Port', 'Sequence Number', 'Acknowledgment Number', 'Data Offset', 'Reserved', 'Flags', 'Window Size', 'Checksum', 'Urgent Pointer']):
                self.tcp_table.setItem(row, 0, QTableWidgetItem(key))
                self.tcp_table.setItem(row, 1, QTableWidgetItem(tcp_fields[key]))
            
            # Update TCP Flags table
            tcp_flags = headers['TCP']['tcp_flags']
            for row, key in enumerate(['CWR', 'ECE', 'URG', 'ACK', 'PSH', 'RST', 'SYN', 'FIN']):
                self.flags_table.setItem(row, 0, QTableWidgetItem(key))
                self.flags_table.setItem(row, 1, QTableWidgetItem('High' if tcp_flags[key] == '1' else 'Low'))
        except Exception as e:
            print(f"Error in table update: {e}")
            self.status_label.setText("Error: Failed to update tables.")
            QMessageBox.critical(self, "Error", f"Failed to update tables: {e}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
