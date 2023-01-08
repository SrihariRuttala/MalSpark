import hashlib
import ssdeep
from filetype import GLOBAL
import pefile
import pyimpfuzzy

class hashes:
    
    def __init__(self):
        self.file = "/home/srihari/Documents/projects/malspark/samples/Chapter_3L/Lab03-03.exe"
        self.file_read = open(self.file,'rb').read()
        
    def get_md5(self):
        md5_sum = hashlib.md5(self.file_read).hexdigest()
        return md5_sum
    
    def get_sha1(self):
        sha1_sum = hashlib.sha1(self.file_read).hexdigest()
        return sha1_sum
    
    def get_sha256(self):
        sha256_sum = hashlib.sha256(self.file_read).hexdigest()
        return sha256_sum
    
    def get_sha512(self):
        sha512_sum = hashlib.sha512(self.file_read).hexdigest()
        return sha512_sum
    
    def get_ssdeep(self):
        ssdeep_hash = ssdeep.hash_from_file(self.file)
        return ssdeep_hash

    def get_imphash(self):
        pefile_obj = pefile.PE(self.file)
        imphash = pefile_obj.get_imphash()
        return imphash

    def get_impfuzzy(self):
        impfuzzy_hash = pyimpfuzzy.get_impfuzzy(self.file)
        return impfuzzy_hash

    
obj = hashes()
print(obj.get_md5())
print(obj.get_sha1())
print(obj.get_sha256())
print(obj.get_sha512())
print(obj.get_ssdeep())
print(obj.get_imphash())
print(obj.get_impfuzzy())
    