import magic
import os
import json
import pefile
import subprocess

global GLOBAL
GLOBAL = json.load(open(os.getcwd() + '/config/config.json','r'))

class filetype:
    def __init__(self):
        self.file_path = '/home/srihari/Documents/projects/malspark/samples/Chapter_3L/Lab03-01.exe'
        self.pe = pefile.PE('/home/srihari/Documents/projects/malspark/samples/Chapter_3L/Lab03-01.exe')

    def detect_filetype(self):
        files = os.listdir(GLOBAL["paths"]["samples"])
        file = files[0]
        type_string = magic.from_file("/home/srihari/Documents/projects/malspark/samples/Chapter_3L/"+file)
        type_string = type_string.split(" ")
        if type_string[0] == "PE32":
            if type_string[2] == "(console)":
                return "PE32", "console"
            elif type_string[2] == "(GUI)":
                return "PE32", "GUI"
            elif type_string[2] == "(DLL)":
                if type_string[3] == "(GUI)":
                    return "DLL", "GUI"
        
        return file, "unsupported"

    def detect_compiler(self):
        for key in self.pe.__dict__.keys():
            print(key)
        if hasattr(self.pe, 'VS_FIXEDFILEINFO'):
            print("Compiler:", pe.VS_FIXEDFILEINFO.CompanyName.decode())
            print("Product version:", pe.VS_FIXEDFILEINFO.ProductVersion)
        else:
            print("not attr")

    def get_fileinfo(self):
        # output = subprocess.check_output(['nfdc', self.file_path]).decode().split('\n')

        # return output
        cmd = "nfdc " + self.file_path
        os.system(cmd)
    
# obj = filetype()
# # l = obj.detect_filetype()
# obj.detect_compiler()
