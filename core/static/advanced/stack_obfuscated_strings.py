import subprocess
import threading

class extract_strings:
	def __init__(self, filepath):
		self.file_path = filepath
		self.stack_strings = []
		self.tight_strings = []
		self.decoded_strings = []

	def get_stack_strings(self):
		
		self.stack_strings = subprocess.check_output(['floss', '--only', 'stack', '-q', '--', self.file_path]).decode().split('\n')
		self.stack_strings = list(filter(lambda a: a != '', self.stack_strings))

		# return stack_strings

	def get_tight_strings(self):
		
		self.tight_strings = subprocess.check_output(['floss', '--only', 'tight', '-q', '--', self.file_path]).decode().split('\n')
		self.tight_strings = list(filter(lambda a: a != '', self.tight_strings))

		# return tight_strings

	def get_decoded_strings(self):
		
		self.decoded_strings = subprocess.check_output(['floss', '--only', 'decoded', '-q', '--', self.file_path]).decode().split('\n')
		self.decoded_strings = list(filter(lambda a: a != '', self.decoded_strings))

		# return decoded_strings


obj = extract_strings('/home/srihari/Documents/projects/malware_stats/stack/hello.exe')
stack = threading.Thread(target = obj.get_stack_strings)
tight = threading.Thread(target = obj.get_tight_strings)
decoded = threading.Thread(target = obj.get_decoded_strings)

stack.start()
tight.start()
decoded.start()

# print(obj.stack_strings)

stack.join()
tight.join()
decoded.join()

print(obj.stack_strings)
print(obj.tight_strings)
print(obj.decoded_strings)
# print(obj.get_stack_strings())
# print(obj.get_tight_strings())
# print(obj.get_decoded_strings())
