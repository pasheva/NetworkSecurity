"""
Author: Mariya Pasheva
OS: Manjaro Linux 5.4
Class: CS494 Network Security HW4 Proxy
"""
import socket
import sys
from _thread import *
import threading
import signal


"""
 Get the line at which the data has occured
"""
def get_error_linenum()->int:
    exc_type, exc_obj, tb = sys.exc_info()
    linenum = tb.tb_lineno
    return linenum

"""
    Hadnles to end the script with Ctr+C
"""
def close_process(signal_recv, frame):
    print("\n[-] Proxy server has been shut down")
    exit()

"""
Running:
    python3 proxy.py [-m [active/passive] listeningip listeningport
        -m: The mode you want your proxy to operate, which will either be active or passive.
        - listeningip: The IP address your proxy will listen on connections on. 
        - listeningport: The port your proxy will listen for connections on.
        
    @return tuple of the mode, ip and port.
"""
def parse_args() -> tuple:
    mode = 0
    if str(sys.argv[2]) == "active":
        mode = 1
    listening_ip = str(sys.argv[3])
    listening_port = str(sys.argv[4])
    return mode, listening_ip, listening_port


"""
    Establishing  a connection to the end server. 
    
    @param host is the host address
    @param port 
    @param stream is the connection stream
    @param data the client browser data request
    
"""
def proxy_server(host, port, stream, data):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        s.send(data)

        while True:
                reply_data = s.recv(8129)
                if len(reply_data)>0:
                    stream.send(reply_data)
                    print("[+] Sending reply")
        s.close()
        stream.close()

    except socket.error:
        print("[+] Error in proxy server occurred. Look at line %s" % get_error_linenum())
        s.close()
        stream.close()
        sys.exit(1)
    

"""
    Parsing the connection details
    
    Example:
    CONNECT www.google.com:443 HTTP/1.1
    User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:75.0) Gecko/20100101 Firefox/75.0
    Proxy-Connection: keep-alive
    Connection: keep-alive  
    Host: www.google.com:443
    
    @param stream the connection stream
    @param data the client browser data request
    @param address of the connection

"""
def parse_conct(stream, data, address):
    try:
        req = data.decode('utf-8').split('\n')[0]
        url = req.split(' ')[1]
        host = " "
        port = -1
        http_pos = url.find("://")
        if http_pos == -1:
            temp = url
        else:
            temp = url[(http_pos+3):]

        port_pos = temp.find(":")
        host_pos = temp.find("/")
        if host_pos == -1:
            host_pos = len(temp)
        if port_pos == -1 or host_pos < port_pos :
            port = 80
            host = temp[:host_pos]
        else:
            port = int((temp[(port_pos+1):][:host_pos-port_pos-1]))
            host = temp[:port_pos]

        proxy_server(host, port, stream, data)

    except Exception:
        print("[-] Error in parsing encountered. Look at line: %s"  % get_error_linenum())


"""
    Setting up a socket and listening for incoming connections. 
"""
def start(listening_ip,listening_port):
    try:
        #input socket
        port = int(listening_port)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((listening_ip, port))
        s.listen(10)
        print("\n[+] Socket started successfully")
    except Exception:
        print("\n[-] Error with creating a socket. Look at line: %s " % get_error_linenum())
        sys.exit(1)

    while True:
        try:
            stream, address = s.accept()
            data = stream.recv(8129)
            t = threading.Thread(target = parse_conct, args = (stream, data, address))
            t.start()
        except KeyboardInterrupt:
            print("\n[-] Proxy server has been shut down")
            s.close()
            sys.exit(1)
    s.close()


def main():
    signal.signal(signal.SIGINT, close_process)
    # script flag mode ip port
    if len(sys.argv) != 5:
        print("[-] Correct number of arguments not provided. ")
        print("\n[-] Run as: python proxy.py [-m [active/passive] listeningip listeningport ")
        exit(1)

    mode, listening_ip, listening_port = parse_args()

    start(listening_ip,listening_port)


if __name__ == "__main__":
    main()