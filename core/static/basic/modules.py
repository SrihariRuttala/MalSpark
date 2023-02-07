import pefile

class modules:
    def __init__(self, file_path):
        self.pe = pefile.PE(file_path)

    def get_imports(self):
    	imports_dict = {}

    	for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            key = str(entry.dll)[2:-1].lower()
            imports_dict[key] = []
            for imp in entry.imports:
            	imports_dict[key].append(str(imp.name)[2:-1])

    	return imports_dict

    def get_exports(self):
    	exports_list = []
    	if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
    		for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
    			exports_list.append(str(exp.name)[2:])
    	return exports_list