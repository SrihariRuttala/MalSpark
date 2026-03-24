import pefile
from hashlib import md5
import os

class pesection:
    def __init__(self, filepath):
        file_path = filepath
        self.pe = pefile.PE(file_path)
        self.size = os.path.getsize(file_path)

    def parse_pe(self):
        section_data = []
        for section in self.pe.sections:
            Name = section.Name.decode()
            VirtualAddress = hex(section.VirtualAddress)
            VirtualSize = hex(section.Misc_VirtualSize)
            RawAddress = hex(section.PointerToRawData)
            RawDataSize = section.SizeOfRawData
            Entropy = section.get_entropy()
            Ratio = (section.SizeOfRawData / self.size) * 100
            section = [Name, VirtualAddress, VirtualSize, RawAddress, RawDataSize, Entropy, Ratio]
            section_data.append(section)
        return section_data

    def get_subsystem(self):
        subsystem = self.pe.OPTIONAL_HEADER.Subsystem
        if subsystem == pefile.SUBSYSTEM_TYPE['IMAGE_SUBSYSTEM_NATIVE']:
            return "Native"
        elif subsystem == pefile.SUBSYSTEM_TYPE['IMAGE_SUBSYSTEM_WINDOWS_GUI']:
            return "Windows GUI"
        elif subsystem == pefile.SUBSYSTEM_TYPE['IMAGE_SUBSYSTEM_WINDOWS_CUI']:
            return "Windows Console"
        else:
            return "Unknown"