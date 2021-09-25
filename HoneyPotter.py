import socket
import atexit
import dothat.lcd as lcd
import dothat.backlight as backlight
import threading
import sys
import requests
import paramiko
import sqlite3
from signal import signal, SIGINT

from threading import Lock
from requests import get
from datetime import datetime, date

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    OKMAGENTA = '\033[95m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

ENABLE_LOGGING = True

SSH_BANNER = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1"

paramiko.util.log_to_file("/tmp/paramiko.log")
con = sqlite3.connect('honeypotter.db', check_same_thread=False)
db = con.cursor()

curr_daily_reports = 0
max_daily_reports = 5000

abuse_IPDB_key=""

ip = get('https://api.ipify.org').text

# Local IP for the honeypot to listen on (TCP)
LHOST = '0.0.0.0'

# Banner displayed when connecting to the honeypot
BANNER = 'Ubuntu 14.04 LTS\nlogin: '

# Socket timeout in seconds
TIMEOUT = 30

# Backlight timeout in seconds
BACKLIGHT_TIMEOUT = 10

THREADS = {}
listener = {}
QUIT_REQUEST = False
PROTOCOLS={
    "21": "FTP",
    "22": "SSH",
    "23": "Telnet",
    "25": "SMTP",
    "80": "HTTP",
    "443": "HTTPS",
    "3306": "MySQL",
    "5900": "VNC",
    "6379": "Redis"
    }

mutex = Lock()

ssh_host_key = paramiko.RSAKey(filename="test_rsa.key")    

def shutdown(signal_received, frame):
    QUIT_REQUEST = True
        
    for proto in PROTOCOLS:
        print '\n[*] Port '+ str(proto) +' is shutting down!'
        listener[proto].close()
        THREADS[proto].join()

def main():
    global PROTOCOLS

    startup()

    create_db()
    get_current_api_usage()

    update_graph()

    signal(SIGINT, shutdown)

    for proto in PROTOCOLS:
        THREADS[str(proto)] = threading.Thread(target=start_honeypot, args=(int(proto),PROTOCOLS[str(proto)])) 
        THREADS[str(proto)].start()

def startup():
    global abuse_IPDB_key

    atexit.register(exit_handler)

    lcd.clear()
    lcd.set_cursor_position(0,0)
    lcd.write("MrLukeKR's")
    lcd.set_cursor_position(0,1)
    lcd.write("HoneyPotter")

    for x in range(360):
        backlight.sweep((360.0 - x) / 360.0)

    set_backlight(0,0,255)
    lcd.clear()
    lcd.set_cursor_position(0,0)
    lcd.write("Listening on:")
    lcd.set_cursor_position(0,1)
    lcd.write(ip)

    print '[*] ' + bcolors.OKBLUE + 'Honeypot starting on ' + LHOST + ' (Public IP: ' + ip + ')' + bcolors.ENDC

    with open("reportAbuseAPIKey.txt", "r") as apikey:
        abuse_IPDB_key = apikey.read().replace('\n', '')        

def start_honeypot(port, service_desc):
    print '[*] ' + bcolors.OKBLUE + 'Service listener starting on port ' + str(port) + ' (' + service_desc + ')' + bcolors.ENDC
    listener[str(port)] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener[str(port)].setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener[str(port)].bind((LHOST, port))
    listener[str(port)].listen(100)

    while not QUIT_REQUEST:
        insock, address = listener[str(port)].accept()
        insock.settimeout(TIMEOUT)
        conn = threading.Thread(target=handle_connection, args=(port, address[0], address[1], insock))
        conn.start()

def handle_connection(lport, rhost, rport, insock):
    global PROTOCOLS, ssh_host_key

    print '[+] ' + bcolors.OKCYAN + 'Honeypot connection from ' + rhost + ':' + str(rport) + ' on port ' + str(lport) + bcolors.ENDC

    set_backlight(255,255,0)
    lcd.clear()
    lcd.set_cursor_position(0,0)
    lcd.write("Connection from:")
    lcd.set_cursor_position(0,1)
    lcd.write(rhost)

    username=''
    password=''

    report_comment = "UTC Time: " + str(datetime.utcnow()) + "\n"
    report_comment += "Source: " + rhost + ":" + str(rport) + "\n"
    report_comment += "Protocol: " + PROTOCOLS[str(lport)]  + "\n"

    try:
        #insock.send(BANNER)
        #data = insock.recv(1024)
   
        lcd.set_cursor_position(0,2)
        lcd.write(PROTOCOLS[str(lport)])
    
        set_backlight(255,0,0)

        abuse_cat=(14,15)

        username = ''
        password = ''

        if lport==22:
            ssh_sess = paramiko.Transport(insock)

            try:
                ssh_sess.load_server_moduli()
            except:
                print '[x] Failed to load moduli'
            ssh_sess.add_server_key(ssh_host_key)
            ssh_sess.local_version = SSH_BANNER
            server_handler = SSHServerHandler(rhost)
            try:
                ssh_sess.start_server(server=server_handler)
            except:
                print '[x] SSH negotiation failed'
            else:
                try:
                    chan = ssh_sess.accept(10)
                except:
                    print '[x] Could not open channel'
                else:
                    if chan is None:
                        print("[?] No channel")
                    else:
                        chan.settimeout(10)
                        if ssh_sess.remote_mac != '':
                            mac = "MAC Address: " + ssh_sess.remote_mac
                            print '[?]\t' + mac
                            report_comment += mac

                        server_handler.event.wait(10)
                        if not server_handler.event.is_set():
                            print '[X] Client never asked for a shell'
                            chan.close()
                        else:
                            chan.send("Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-128-generic x86_64)\r\n\r\n")
                            run = False
                            while run:
                                chan.send("$ ")
                            chan.close()

            username = server_handler.user_attempt
            password = server_handler.pass_attempt

            if username != '':
                abuse_cat = (18,22)
            else:
                abuse_cat = (22)

            print '[>]\tUser: ' + username + "\tPass: " + password
            
            ssh_sess.close()

        elif lport==21:
            abuse_cat = (18,5)

        if username != '':
            report_comment += "Username: " + username + '\n'
        if password != '':
            report_comment += "Password: " + password + '\n'    

        if rhost == ip:
            print '[-] ' + bcolors.WARNING + 'Ignoring -- This is from our public IP address' + bcolors.ENDC
        elif rhost.split('.')[0] == "192" and rhost.split('.')[1] == "168" and rhost.split('.')[2] == "1" :
            print '[-] ' + bcolors.WARNING + 'Ignoring -- This is from our local network' + bcolors.ENDC
        else:
            report_ip(rhost, abuse_cat, report_comment)
    except socket.error, e:
        print('[x] ' + bcolors.FAIL + 'Error: ' + str(e) + bcolors.ENDC)
    finally:
        insock.close()

    sys.stdout.flush()

def log_debug(text):
    global ENABLE_LOGGING

    if not ENABLE_LOGGING:
        return

    print text

def report_ip(ip_addr, abuse_types, comment):
    global abuse_IPDB_key, reported_IPs, curr_daily_reports, max_daily_reports

    if type(abuse_types) is tuple:
        data = { "ip": ip_addr, "categories": ','.join(map(str, abuse_types)), "comment": comment }
    else:
        data = { "ip": ip_addr, "categories": str(abuse_types), "comment": comment }
    headers = { "Key": abuse_IPDB_key, "Accept": "application/json" }

    db.execute("SELECT reports FROM ip_addresses WHERE address='" + ip_addr + "';")
    res = db.fetchall()

    ip_logged = len(res) > 0 and res[0] > 0

    lcd.clear()
    lcd.set_cursor_position(0,0)

    if curr_daily_reports < max_daily_reports:
        set_backlight(0,255,0)

        resp = requests.post("https://api.abuseipdb.com/api/v2/report", data=data, headers=headers)
        print("[!] " + bcolors.OKGREEN + "Reported IP " + ip_addr + bcolors.ENDC)

        lcd.write("Reported IP:")
        lcd.set_cursor_position(0,1)
        lcd.write(ip_addr)

        db.execute("INSERT OR IGNORE INTO api VALUES ('" + str(date.today()) + "', 0);")
        db.execute("UPDATE api SET count = count + 1 WHERE date='" + str(date.today()) + "';")

        if ip_logged:
            db.execute("UPDATE ip_addresses SET reports = reports + 1 WHERE address='" + ip_addr + "';") 
        else:
            db.execute("INSERT INTO ip_addresses VALUES('" + ip_addr + "', 1);")
    else:
        print("[!] " + bcolors.OKMAGENTA + "Queued IP " + ip_addr + bcolors.ENDC)

        set_backlight(255,0,255)

        lcd.write("Queued IP:")
        lcd.set_cursor_position(0,1)
        lcd.write(ip_addr)

    mutex.acquire()
    curr_daily_reports += 1
    update_graph()
    mutex.release()
    
    # TODO: Add to IP address db
    # TODO: Reset count at 1AM UK time

def update_graph():
    backlight.set_graph(float(curr_daily_reports) / float(max_daily_reports))

def set_backlight(r,g,b):
    backlight.left_rgb(r, g, b)
    backlight.mid_rgb(r, g, b)
    backlight.right_rgb(r, g, b)

def exit_handler():
    global PROTOCOLS, THREADS
    
    print '\n[*] Honeypot is shutting down!'

    for proto in PROTOCOLS:
        print '\n[*] Port '+ str(proto) +' is shutting down!'
        THREADS[proto].join()
        listener[proto].close()
    

def create_db():
    db.execute('CREATE TABLE IF NOT EXISTS api (date TEXT PRIMARY KEY, count INTEGER);')
    db.execute('CREATE TABLE IF NOT EXISTS ip_addresses (address TEXT PRIMARY KEY, reports INTEGER);')
    db.execute('CREATE TABLE IF NOT EXISTS reports (id INTEGER PRIMARY KEY AUTOINCREMENT, address TEXT, reported INTEGER, abuse_types TEXT, comment TEXT);')

def get_current_api_usage():
    global curr_daily_reports

    db.execute("SELECT count FROM api WHERE date='" + str(date.today()) + "';")

    rows = db.fetchall()
    if len(rows) > 0:
        curr_daily_reports = rows[0]

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        shutdown()    

class SSHServerHandler (paramiko.ServerInterface):
    user_attempt = ''
    pass_attempt = ''
    client_ip = ''
    
    def __init__(self, client_ip):
        log_debug('[?] __init__()')
        self.client_ip = client_ip
        self.event = threading.Event()

    def check_auth_password(self, username, password):
        log_debug('[?] check_auth_password()')

        self.user_attempt = username
        self.pass_attempt = password

        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        log_debug('[?] get_allowed_auths()')
        return 'publickey,password,none'

    def check_auth_publickey(self, username, key):
        fingerprint = u(hexlify(key.get_fingerprint()))
        log_debug('[?] client public key ({}): username: {}, key name: {}, md5 fingerprint: {}, base64: {}, bits: {}'.format(
                    self.client_ip, username, key.get_name(), fingerprint, key.get_base64(), key.get_bits()))
        return paramiko.AUTH_PARTIALLY_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        log_debug('[?] check_channel_request()')
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED

    def check_channel_shell_request(self, channel):
        log_debug('[?] check_channel_shell_request()')
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        log_debug('[?] check_channel_pty_request()')
        return True

    def check_channel_exec_request(self, channel, command):
        log_debug('[?] check_channel_exec_request()')

        command_text = str(command.decode("utf-8"))

        print('[>] Client sent command: ' + command)
        return True
