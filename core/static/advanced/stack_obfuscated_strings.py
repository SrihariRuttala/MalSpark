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

		return self.stack_strings

	def get_tight_strings(self):
		
		self.tight_strings = subprocess.check_output(['floss', '--only', 'tight', '-q', '--', self.file_path]).decode().split('\n')
		self.tight_strings = list(filter(lambda a: a != '', self.tight_strings))

		return self.tight_strings

	def get_decoded_strings(self):
		
		self.decoded_strings = subprocess.check_output(['floss', '--only', 'decoded', '-q', '--', self.file_path]).decode().split('\n')
		self.decoded_strings = list(filter(lambda a: a != '', self.decoded_strings))

		return self.decoded_strings