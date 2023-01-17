def fun_generator():
	for i in range(10):
		yield i


obj = fun_generator()

# print(type(obj))

print(next(obj))
print(next(obj))
