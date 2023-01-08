import string
from filetype import GLOBAL

class strings:
	
	def __init__(self):
		self.file = "/home/srihari/Documents/projects/malspark/samples/Chapter_3L/Lab03-03.exe"
		self.printable = set(string.printable)
		self.data = open(self.file, 'rb').read()

	def extract_strings(self):
		# print(self.data)
		flag = 0
		extracted_string = ""
		self.printable.remove("\n")
		self.printable.remove('\x0c')
		self.printable.remove("\x0b")
		for char in self.data:
			char = chr(char)
			if char in self.printable:
				if flag ==0 and char == " ":
					pass
				else:
					extracted_string += char
					flag =1
			elif len(extracted_string) >=4:
				print(extracted_string)
				extracted_string = ""
				flag = 0
			else:
				flag = 0
				extracted_string = ""

obj = strings()
obj.extract_strings() 
