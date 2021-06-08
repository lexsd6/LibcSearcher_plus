import subprocess
from collections import defaultdict
import os
import re
import sys


class  finder(object):
	def __init__(self,func=None, addr=None,num=None):
		self.symbols={}
		self.libcbase=None
		self.__libc_path=os.path.normpath(os.path.join(os.path.realpath(os.path.dirname(__file__)), "../libc-database/db/"))
		self.__fun_news=defaultdict(int)
		self.__check(func,addr)
		self.__search(num)
	
	def __check(self,func,addr):
		if  type(func)!= str:
			print("[x]wrong: func name not is string !")
			return None
		if  type(addr)!= int:
			print("[x]wrong: func address not is int !")
			return None
		self.__fun_news['func']=func
		self.__fun_news['addr']=addr
		
	def __bind(self,libcsname):
		with open(self.__libc_path, 'r') as f:
			self.symbols=dict([i.strip('\n').split(' ')[0],int(i.strip('\n').split(' ')[-1],16)] for i in f.readlines())			
		self.libcbase=self.__fun_news['addr']-self.symbols[self.__fun_news['func']]

	def dump(self,func):
		if self.libcbase:	
			funcaddr=self.libcbase+self.symbols[func]
			return funcaddr
		
	def __search(self,num):
		if self.__fun_news['addr'] and self.__fun_news['func']:
			reconst=re.compile("^%s .*%x"%(self.__fun_news['func'],self.__fun_news['addr']&0xfff))
			name=[]
			libcs=[]
			for root,dirs,files in os.walk(self.__libc_path):
				for i in files:
					if os.path.splitext(i)[1]=='.symbols':
						name.append(i) 

			for fname in name:						
				with open(os.path.join(self.__libc_path,fname), 'r') as f:
					data=f.read().rsplit('\n')
					if any(map(lambda line: reconst.match(line), data)):
	                    			libcs.append(fname)
		
			if len(libcs)== 0:
				print("[x]wrong: No matched, Make sure you supply a valid function name or add more libc in "+self.__libc_path)
				return None
			elif len(libcs)>1:
				
					print("multi libc results:")
					for x in range(len(libcs)):
						with open(os.path.join(self.__libc_path,libcs[x].rstrip('.symbols')+'.info'), 'r') as f:
							info=f.read().rstrip('\n')
						print("[-]%2d: %s(source from:%s)" % (x,libcs[x].rstrip('.symbols'),info))
					
					while True:
								try:	
									if num==None:					
										libcs_id = input("[!] you can choose it by hand\nOr type 'exit' to quit:")
										libcs_id = int(libcs_id)
									else :
										libcs_id=num
										num=None
								except:
										break
								if libcs_id == "exit" or libcs_id == "quit":
									sys.exit(0)
								else:
									try:
										libcs_id = int(libcs_id)
										libcs= libcs[libcs_id]
										self.__libc_path=os.path.join(self.__libc_path,libcs)
										self.__bind(libcs)
										with open(self.__libc_path.rstrip('.symbols')+'.info', 'r') as f:
											info=f.read().rstrip('\n')
											print("[+] %s baseaddr=%s (source from:%s)" % (libcs.rstrip('.symbols'),hex(self.libcbase),info))
										break
									except:
											continue		
			else :
				libcs=libcs[0]
				self.__libc_path=os.path.join(self.__libc_path,libcs)
				self.__bind(libcs)
				
				with open(self.__libc_path.rstrip('.symbols')+'.info', 'r') as f:
						info=f.read().rstrip('\n')
				print("[*] %s baseaddr=%s (source from:%s)" % (libcs.rstrip('.symbols'),hex(self.libcbase),info))
				
	def ogg(self,level=0,num=None):
		so_path=self.__libc_path.rstrip('.symbols')+'.so'
		if os.path.exists(so_path)==False:
			print("[x]wrong:don't find .so file in "+self.__libc_path)
			return None
		else:
			try:
				x=subprocess.check_output(["one_gadget","--level",str(level),so_path])
			
			except FileNotFoundError:
				print('[x]find out one_gadget')
			
			else:
				oggtext=x.decode().split('\n\n')
				oggls=re.findall(r'0x[0-9A-F]+ ', x.decode(), re.I)
				for i in range(len(oggls)):
					print('[*]%2d: %s'%(i,oggtext[i]))
				while True:
					try:
						if num==None:
							in_id = input("[!] you can choose a gadget by hand or type 'exit' to quit:")
							in_id = int(in_id)
						else :
							in_id=num
							num=None
					except:
						break
					if in_id == "exit" or in_id == "quit":
					    break
					try:
					    
					    oggls = int(oggls[in_id],16)
					    print('[*] you choose gadget: %s'%(hex(oggls)))
					    break
					except:
					    continue
				return oggls+self.libcbase


if __name__ == "__main__":
	
	x=finder('write',0xf7eb4c90,num=11)
	x.ogg(num=0)
	x.ogg(num=11)
	print(x.dump('read'))
	print(x.libcbase)
	#print(x.sym['read'])
	print(x.symbols['read'])
	#test('x')
	#x.search()
