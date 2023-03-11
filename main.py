from core.static.basic.filetype import filetype
from core.static.basic.hashes import hashes
from colorama import Fore, Back, Style
from core.static.basic.strings import strings
from core.static.basic.pesection import pesection
from termcolor import colored 
from tabulate import tabulate
from prettytable import PrettyTable
from core.static.basic.modules import modules
from core.static.basic.resources import resources
from core.static.advanced.stack_obfuscated_strings import extract_strings
from core.static.advanced.detectpacker import packer
import threading


class colors:
    black = '\033[30m'
    red = '\033[31m'
    green = '\033[32m'
    orange = '\033[33m'
    blue = '\033[34m'
    purple = '\033[35m'
    cyan = '\033[36m'
    lightgrey = '\033[37m'
    darkgrey = '\033[90m'
    lightred = '\033[91m'
    lightgreen = '\033[92m'
    yellow = '\033[93m'
    lightblue = '\033[94m'
    pink = '\033[95m'
    lightcyan = '\033[96m'
    end = '\033[0m'

class print_output:
	def __init__(self):
		self.file_path = "dummy"
		self.color = colors()


	def get_hashes(self):
		hash = hashes()
		print('\n\033[1m'  + '\033[33m' + '[+] ' + '\033[96m' + 'Checking Hashes... \033[0m')
		print(Fore.GREEN + 'md5 : ' + Fore.BLUE + str(hash.get_md5())) 
		print(Fore.GREEN + 'sha1 : ' + Fore.BLUE + str(hash.get_sha1()))
		print(Fore.GREEN + 'sha256 : ' + Fore.BLUE + str(hash.get_sha256()))
		print(Fore.GREEN + 'sha512 : ' + Fore.BLUE + str(hash.get_sha512()))
		print(Fore.GREEN + 'ssdeed : ' + Fore.BLUE + str(hash.get_ssdeep()))
		print(Fore.GREEN + 'imphash : ' + Fore.BLUE + str(hash.get_imphash()))
		print(Fore.GREEN + 'impfuzzy : ' + Fore.BLUE + str(hash.get_impfuzzy()))

	def get_filetype(self):
		print('\n\033[1m'  + '\033[33m' + '[+] ' + '\033[96m' + 'Checking File Information... \033[0m')
		file = filetype()
		output, self.packed = file.get_fileinfo()
		for i in output:
			print(i)

	def get_strings(self):
		print('\033[1m'  + '\033[33m' + '[+] ' + '\033[96m' + 'Extracting Strings... \033[0m')
		obj = strings()
		extracted_strings = obj.extract_strings()  
		string = obj.advanced_strings()
		strings1 = obj.pattern_evalution()
		imports, exports, extracted_strings = obj.get_modules()
		
		for i in range(len(extracted_strings)):
			if i%3 ==0 and i!=0:
				print()
			print(f'{extracted_strings[i]:<35}', end='\t')
		print()
		print('\n\033[1m'  + '\033[33m' + '[+] ' + '\033[96m' + 'Worth Looking Strings... \033[0m')
		for i in range(len(string)):
			if i%3 == 0 and i!=0:
				print()

			print(f'{self.color.red}{string[i]:<35}', end='\t')

		for i in range(len(strings1)):
			for j in range(1, len(strings1[i])):
				if ((i+j)%3 ==0):
					print()
				print(f'{strings1[i][j]:<35}', end='\t')

		print('\033[0m')
		if len(imports) != 0:
			print('\n\033[1m'  + '\033[33m' + '[+] ' + '\033[96m' + 'Imports from Strings... \033[0m')
			for i in range(len(imports)):
				if i%3 == 0 and i!=0:
					print()

				print(f'{self.color.blue}{imports[i]:<35}', end='\t')

		if len(exports) != 0:
			print('\n\033[1m'  + '\033[33m' + '[+] ' + '\033[96m' + 'Exports from Strings... \033[0m')
			for i in range(len(exports)):
				if i%3 == 0 and i!=0:
					print()

				print(f'{self.color.blue}{exports[i]:<35}', end='\t')
		print('\033[0m')

	def get_pesections(self):
		print('\n\033[1m'  + '\033[33m' + '[+] ' + '\033[96m' + 'Extracting PESection Information... \033[0m')
		obj = pesection()
		data = obj.parse_pe()
		head = ['Name', 'VirtualAddress', 'VirtualSize', 'RawAddress', 'RawDataSize', 'Entropy', 'Ratio']
		print(tabulate(data, headers=head, tablefmt="grid")) 

	def get_modules(self):
		obj = modules("/home/srihari/Documents/projects/malspark/samples/Chapter_3L/Lab03-04.exe")
		imports = obj.get_imports()
		exports = obj.get_exports()
		if len(imports) != 0:
			print('\n\033[1m'  + '\033[33m' + '[+] ' + '\033[96m' + 'Extracting Imports... \033[0m')
			print(tabulate(imports, headers='keys', tablefmt='fancy_grid'))

		if len(exports) != 0:
			print('\n\033[1m'  + '\033[33m' + '[+] ' + '\033[96m' + 'Extracting Exports... \033[0m')
			print(tabulate(imports, headers='keys', tablefmt='fancy_grid'))

	def get_resources(self):
		obj = resources("/home/srihari/Documents/projects/malware_stats/Practical Malware Analysis Labs/BinaryCollection/Chapter_1L/Lab01-04.exe")
		names = obj.get_resource_names()
		if names != None:
			print('\n\033[1m'  + '\033[33m' + '[+] ' + '\033[96m' + 'Extracting Resource Names... \033[0m')
			if len(names) > 10:
				print(f'{self.color.yellow}No.of exports are greater than 10. Do you want to print them?[Y/N] default[N] : ', end="")
				flag = input()
				if flag == 'Y':
					for i in names:
						print(i)
			else:
				for i in names:
					print(i)

	def deobfuscate(self):
		obj = extract_strings('/home/srihari/Documents/projects/malware_stats/stack/hello.exe')

		print('\n\033[1m'  + '\033[34m' + '[+] Do you want to check for stack strings, tight strings and defuscation?[Y/N] default[N] : \033[0m', end="")
		flag = input()
		if flag == 'Y':
			print('\n\033[1m'  + '\033[33m' + '[+] Please hang tight it will take some time to give results... \033[0m')
			stack = threading.Thread(target = obj.get_stack_strings)
			tight = threading.Thread(target = obj.get_tight_strings)
			decoded = threading.Thread(target = obj.get_decoded_strings)

			stack.start()
			tight.start()
			decoded.start()

			stack.join()
			tight.join()
			decoded.join()

			stack = obj.stack_strings
			tight = obj.tight_strings
			decoded = obj.decoded_strings

			if len(stack) != 0:
				print('\n\033[1m'  + '\033[33m' + '[+] ' + '\033[96m' + 'Extracting Stack Strings... \033[0m')
				for i in range(len(stack)):
					if i%3 == 0 and i!=0:
						print()
					print(f'{self.color.blue}{stack[i]:<35}', end='\t')
				print()
			else:
				print(f'\n\033[1m{self.color.green}[+] No stack strings found')
			if len(tight) != 0:
				print('\n\033[1m'  + '\033[33m' + '[+] ' + '\033[96m' + 'Extracting Tight Strings... \033[0m')
				for i in range(len(tight)):
					if i%3 == 0 and i!=0:
						print()
					print(f'{self.color.blue}{tight[i]:<35}', end='\t')
				print()
			else:
				print(f'\n\033[1m{self.color.green}[+] No tight strings found')
			if len(decoded) != 0:
				print('\n\033[1m'  + '\033[33m' + '[+] ' + '\033[96m' + 'Deobfuscating Strings... \033[0m')
				for i in range(len(decoded)):
					if i%3 == 0 and i!=0:
						print()
					print(f'{self.color.blue}{decoded[i]:<35}', end='\t')
				print()
			else:
				print(f'\n\033[1m{self.color.green}[+] No obfuscated strings found')
		else:
			return

	def detect_packer(self):
		obj = packer('/home/srihari/Documents/projects/malspark/samples/upx_ADExplorer.exe')
		print('\n\033[1m'  + '\033[33m' + '[+] ' + '\033[96m' + 'Checking if PE is packed... \033[0m')
		dll, imports, flag = obj.min_imports_stats()
		if flag == True:
			print(f'{self.color.red}Dll count : {dll}')
			print(f'{self.color.red}Imported functions count : {imports}')
		else:
			print(f'{self.color.green}Dll count : {dll}')
			print(f'{self.color.red}Imported functions count : {imports}')
		section_flag, sections = obj.abnormal_section_names()
		if section_flag == True:
			print(f'{self.color.red}Abnormal sections : ', end="")
			for i in range(len(sections)):
				if i!=len(sections)-1:
					print(sections[i], end=", ")
				else:
					print(sections[i])
		else:
			print(f'\n\033[1m{self.color.green}[+] No Abnormal Sections Found')
		
		entropy, entropy_flag = obj.abnormal_entropy()
		
		if entropy_flag == True:
			print(f'{self.color.red}Entropy : {entropy}')
		else:
			print(f'{self.color.green}Entropy : {entropy}')
		for i in self.packed:
			print(i.strip())

if __name__ == '__main__':
	obj = print_output()
	obj.get_hashes()
	obj.get_filetype()
	obj.get_strings()
	obj.get_pesections()
	obj.get_modules()
	obj.get_resources()
	obj.deobfuscate()
	obj.detect_packer()