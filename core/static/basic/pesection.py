import pefile
from hashlib import md5
import os

class pesection:
    def __init__(self):
        file_path = '/home/srihari/Documents/projects/malware_stats/Practical Malware Analysis Labs/BinaryCollection/Chapter_1L/Lab01-04.exe'
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
            # print("Ratio: {:.2f}%".format(Ratio))
            section = [Name, VirtualAddress, VirtualSize, RawAddress, RawDataSize, Entropy, Ratio]
            section_data.append(section)
            # section_dict[Name] = section
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

# pe = pesection('/home/srihari/Documents/projects/malspark/samples/upx_ADExplorer.exe')
# print(pe.parse_pe())
# print(pe.get_subsystem())