import magic
import os
import json
import pefile
import subprocess

global GLOBAL
GLOBAL = json.load(open(os.getcwd() + '/config/config.json','r'))

class filetype:
    def __init__(self):
        self.file_path = '/home/srihari/Documents/projects/malware_stats/packed/yoda-crypter_ADExplorer.exe'
        self.pe = pefile.PE('/home/srihari/Documents/projects/malware_stats/packed/yoda-crypter_ADExplorer.exe')

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
        output = subprocess.check_output(['nfdc', self.file_path]).decode().split('\n')
        check_output = subprocess.check_output(['nfdc', self.file_path, "--json"])
        values = json.loads(check_output.decode())
        dict_types = {}
        packed = []
        dict_types["Packer"] = []
        dict_types["Protector"] = []
        dict_types["Cryptor"] = []
        for i in range(len(values['detects'][0]['values'])):
            if values['detects'][0]['values'][i]['type'] == "Packer":
                dict_types["Packer"].append(i+1)
            elif values['detects'][0]['values'][i]['type'] == "Protector":
                dict_types["Protector"].append(i+1)
            elif values['detects'][0]['values'][i]['type'] == "Cryptor":
                dict_types["Cryptor"].append(i+1)

        count = 0
        for i in dict_types:
            for j in dict_types[i]:
                packed.append(output.pop(j - count))
                count += 1
        return output, packed

