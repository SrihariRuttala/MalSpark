import pefile

class modules:
    def __init__(self):
        self.pe = pefile.PE('/home/srihari/Documents/projects/malspark/samples/Chapter_3L/Lab03-02.dll')

    def get_imports(self):
    	imports_dict = {}

    	for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
    		imports_dict[entry.dll] = []
    		for imp in entry.imports:
    			imports_dict[entry.dll].append(imp.name)

    	return imports_dict

    def get_exports(self):
    	exports_list = []
    	if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
    		for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
    			exports_list.append(exp.name)
    	return exports_list



pe = pesection()
# print(pe.get_imports())
print(pe.get_exports())