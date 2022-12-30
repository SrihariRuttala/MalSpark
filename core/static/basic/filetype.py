import magic
import os
import json

global GLOBAL
GLOBAL = json.load(open(os.getcwd() + '/../../../config/config.json','r'))

class filetype:
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
    
obj = filetype()
l = obj.detect_filetype()
print(l)