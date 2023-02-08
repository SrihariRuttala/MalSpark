import yara
import pefile
import sys

sys.path.append('../../../')

from core.static.basic.modules import modules
from core.static.basic.filetype import GLOBAL

class packer:

    def __init__(self, file_path):
        self.pe = pefile.PE('/home/srihari/Documents/projects/malspark/samples/upx_ADExplorer.exe')
        self.rules = yara.compile('/home/srihari/Documents/projects/malspark/yara/packers.yara')
        self.file_path = file_path
        self.threshold = GLOBAL["static"]["advanced"]["imports_threshold"]

    def detect_yara_rules(self):
        matches = self.rules.match(self.file_path)
        for match in matches:
            if match.rule:
                yield match.rule

    def min_imports_stats(self):
        imports_count = 0
        dll_count = 0
        
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            dll_count += 1
            for imp in entry.imports:
                imports_count += 1
        
        packed = False
        
        if (imports_count < (dll_count*2)) or (imports_count < self.threshold):
            packed = True

        return dll_count, imports_count, packed

    def check_imports(self):
        obj = modules(self.file_path)
        imports = obj.get_imports()
        kernel32_imports = imports['kernel32.dll']

        packed = False

        if ('GetModuleHandleA' in kernel32_imports) or ('LoadLibraryA' in kernel32_imports):
            if ('GetProcAddress' in kernel32_imports):
                packed = True

        return packed

    def abnormal_section_names(self):
        predefined_sections =  ['.text', '.bss', '.rdata', '.data', '.rsrc', '.edata', '.pdata', '.debug', '.idata', '.reloc', '.CRT', '.tls', '/4']
        sections = []

        for section in self.pe.sections:
            section_name = section.Name.decode('ISO-8859-1').split('\x00')[0]
            if section_name not in predefined_sections:
                sections.append(section_name)

        if len(sections) != 0:
            return True, sections

        return False, sections
                

    # def abnormal_section_size(self):


obj = packer('/home/srihari/Documents/projects/malspark/samples/upx_ADExplorer.exe')
packers = obj.detect_yara_rules()
print(list(packers))
print(obj.min_imports_stats())
print(obj.check_imports())
print(obj.abnormal_section_names())