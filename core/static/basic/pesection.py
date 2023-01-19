import pefile
from hashlib import md5
import os

class pesection:
    def __init__(self):
        self.pe = pefile.PE('/home/srihari/Documents/projects/malspark/samples/Chapter_3L/Lab03-04.exe')
        self.size = os.path.getsize('/home/srihari/Documents/projects/malspark/samples/Chapter_3L/Lab03-04.exe')

    def parse_pe(self):
        section_list = []
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
            section_list.append(section)
        return section_list

pe = pesection()
print(pe.parse_pe())