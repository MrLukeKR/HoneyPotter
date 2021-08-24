import socket
import atexit
import dothat.lcd as lcd
import dothat.backlight as backlight
import threading
import sys
import requests
import paramiko

from requests import get
from datetime import datetime

ENABLE_LOGGING = False

paramiko.util.log_to_file("/tmp/paramiko.log")

curr_daily_reports = 0
max_daily_reports = 5000

abuse_IPDB_key=""

ip = get('https://api.ipify.org').text

# Local IP for the honeypot to listen on (TCP)
LHOST = '0.0.0.0'

# Banner displayed when connecting to the honeypot
BANNER = 'Ubuntu 14.04 LTS\nlogin: '

# Socket timeout in seconds
TIMEOUT = 10

THREADS = {}
listener = {}
QUIT_REQUEST = False
PROTOCOLS={
    "21": "FTP",
    "22": "SSH",
    "23": "Telnet",
    "80": "HTTP",
    "443": "HTTPS"
    }

ssh_host_key = paramiko.RSAKey(filename="test_rsa.key")    

def main():
    global PROTOCOLS

    startup()
    
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

    print '[*] Honeypot starting on ' + LHOST + ' (Public IP: ' + ip + ')'

    with open("reportAbuseAPIKey.txt", "r") as apikey:
        abuse_IPDB_key = apikey.read().replace('\n', '')        

def start_honeypot(port, service_desc):
    print '[*] Service listener starting on port ' + str(port) + ' (' + service_desc + ')'
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

    print '[+] Honeypot connection from ' + rhost + ':' + str(rport) + ' on port ' + str(lport)

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
            abuse_cat = (18,22)
            ssh_sess = paramiko.Transport(insock)
            ssh_sess.set_gss_host(socket.getfqdn(""))
            try:
                ssh_sess.load_server_moduli()
            except:
                print '[x] Failed to load moduli'
            ssh_sess.add_server_key(ssh_host_key)
            server_handler = SSHServerHandler()
            try:
                ssh_sess.start_server(server=server_handler)
            except:
                print '[x] SSH negotiation failed'
                ssh_sess.close()
            else:
                try:
                    chan = ssh_sess.accept(20)
                    if chan is None:
                        print("[?] No channel")
                except:
                    print '[x] Could not open channel'
                finally:
                    if chan is not None:
                        chan.close()

            username = server_handler.user_attempt
            password = server_handler.pass_attempt
            print '[>]\tUser: ' + username + "\tPass: " + password
            
            ssh_sess.close()

        elif lport==21:
            abuse_cat = (18,5)

        if username != '':
            report_comment += "Username: " + username + '\n'
        if password != '':
            report_comment += "Password: " + password + '\n'    

        if rhost == ip:
            print '[-] Ignoring -- This is from our public IP address'
        elif rhost.split('.')[0] == "192" and rhost.split('.')[1] == "168" and rhost.split('.')[2] == "1" :
            print '[-] Ignoring -- This is from our local network'
        else:
            report_ip(rhost, abuse_cat, report_comment)
    except socket.error, e:
        print('[x] Error: ' + str(e))
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

    data = { "ip": ip_addr, "categories": ','.join(map(str, abuse_types)), "comment": comment }
    headers = { "Key": abuse_IPDB_key, "Accept": "application/json" }

    resp = requests.post("https://api.abuseipdb.com/api/v2/report", data=data, headers=headers)
    print("[!] Reported IP " + ip_addr)

    set_backlight(0,255,0)
    lcd.clear()
    lcd.set_cursor_position(0,0)
    lcd.write("Reported IP:")
    lcd.set_cursor_position(0,1)
    lcd.write(ip_addr)

    curr_daily_reports += 1
    backlight.set_graph(curr_daily_reports / max_daily_reports)
    # TODO: Add to IP address db
    # TODO: Reset count at 1AM UK time
    # TODO: Load count from DB if restarting

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
    

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        QUIT_REQUEST = True
        
        for proto in PROTOCOLS:
            print '\n[*] Port '+ str(proto) +' is shutting down!'
            listener[proto].close()
            THREADS[proto].join()
        

class SSHServerHandler (paramiko.ServerInterface):
    user_attempt = ''
    pass_attempt = ''
    
    def __init__(self):
        log_debug('[?] __init__()')
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        log_debug('[?] check_channel_request()')
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED

    def check_auth_password(self, username, password):
        log_debug('[?] check_auth_password()')

        self.user_attempt = username
        self.pass_attempt = password

        return paramiko.AUTH_SUCCEEDED

    def get_allowed_auths(self, username):
        log_debug('[?] get_allowed_auths()')
        return 'password'