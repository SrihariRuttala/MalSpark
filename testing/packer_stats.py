import pefile
import os
import matplotlib.pyplot as plt


class test:
    def __init__(self):
        self.path = "/home/srihari/Documents/projects/malware_stats/outliers/packed/"
        # self.pe = pefile.PE('/home/srihari/Documents/projects/malspark/samples/upx_ADExplorer.exe')

    def get_imports(self):
        imports_dict = {}
        files = os.listdir(self.path)
        f = []
        imports_count = []
        imports_c = {}
        for i in files:
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

obj = test()
obj.get_imports()