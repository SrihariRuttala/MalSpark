import pefile
import os
import math
import matplotlib.pyplot as plt


class test:
    def __init__(self):
        self.path = "/home/srihari/Documents/projects/malware_stats/not-packed/"
        self.files = os.listdir(self.path)
        # self.pe = pefile.PE('/home/srihari/Documents/projects/malspark/samples/upx_ADExplorer.exe')

    def get_imports(self):
        imports_dict = {}
        f = []
        imports_count = []
        imports_c = {}
        for i in self.files:
            try:
                self.pe = pefile.PE(self.path + str(i)) 
                count = 0
                
                for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                    imports_dict[entry.dll] = 0
                    imports_c[entry.dll] = []
                    for imp in entry.imports:
                        imports_c[entry.dll].append(imp.name)
                        imports_dict[entry.dll] = imports_dict[entry.dll] + 1
                        count += 1

                if count < 100:
                    imports_count.append(count)
                    f.append(i)
                    print(f'{str(i):<30} : ', end="")
                    print(imports_c[b'KERNEL32.DLL'])

                # print("Number of dll's for " + str(i) + " : " + str(len(list(imports_dict.keys()))))
                # print("Number of imports for " + str(i) + " : " + str(count))
                # print()
            except: 
                # files.remove(i)
                pass

        packers = []
        xbar = []
        count = 0
        for i in f:
            count += 1
            xbar.append(count)
            pack = i.split("_")[0]
            packers.append(pack)

        print(xbar)
        print(imports_count)
        print(packers)

        # fig, ax = plt.subplots()

        plt.barh(packers, imports_count, color=['red', 'green'])

        plt.ylabel("No.of imports")
        plt.xlabel("Packers")
        plt.title("imports statistics for different packers")

        plt.show()
        # return imports_dict

    def sections(self):
        predefined_sections =  ['.text', '.bss', '.rdata', '.data', '.rsrc', '.edata', '.pdata', '.debug', '.idata', '.reloc', '.CRT', '.tls', '/4']
        stats_dict = {}
        for i in self.files:
            sections = []
            pe_file = pefile.PE(self.path + i)
            for section in pe_file.sections:
                section_name = section.Name.decode('ISO-8859-1').split('\x00')[0]
                if section_name not in predefined_sections:
                    sections.append(section_name)
            if len(sections) != 0:
                stats_dict[i] = sections
                print(f'{i:<35} : {",".join(str(x) for x in stats_dict[i])}')

        print(len(self.files))
        print(len(list(stats_dict)))
        # for i in stats_dict:
        #     print(f'{i:<10} : {stats_dict[i]}')

    def entropy(self):

        entropy_list = []

        for file in self.files:
            filepath = self.path + file
            byte = [0 for i in range(256)]
            with open(filepath, 'rb') as f:
                data = f.read()
                entropy = 0
                for i in range(len(data)):
                    byte[data[i]] += 1

                for i in range(256):
                    temp = byte[i]/len(data)
                    if temp:
                        entropy += (-math.log(temp)/math.log(2))* byte[i]

                entropy = entropy/len(data)
            entropy_list.append(entropy)
            # print(f' {file:<37} : {entropy}')

        print(min(entropy_list))
        print(max(entropy_list))
        print(sum(entropy_list)/len(entropy_list))

 

obj = test()
obj.entropy()