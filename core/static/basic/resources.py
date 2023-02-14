import pefile

class resources:
	def __init__(self, filepath):
		self.filepath = filepath
		self.pe = pefile.PE(self.filepath)

	def get_resource_names(self):
		try:
			if not hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
				print("hell")
			else:
				resource_names = []
				for resource_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
					if resource_type.name is not None:
						resource_names.append(resource_type.name.decode())
					else:
						resource_names.append(pefile.RESOURCE_TYPE.get(resource_type.struct.Id))

					if resource_type.directory is not None:
						for resource_id in resource_type.directory.entries:
							if resource_id.name is not None:
								resource_names.append(resource_id.name.decode())
							else:
								resource_names.append(pefile.RESOURCE_TYPE.get(resource_id.struct.Id))

							if resource_id.directory is not None:
								for resource_lang in resource_id.directory.entries:
									print(resource_lang.data.lang)
									resource_names.append(pefile.LANG.get(resource_lang.data.lang))
				return resource_names
		except Exception as e:
			print("Exception : " + str(e))

			return None	


obj = resources("/home/srihari/Documents/projects/malware_stats/Practical Malware Analysis Labs/BinaryCollection/Chapter_1L/Lab01-04.exe")
print(obj.get_resource_names())
