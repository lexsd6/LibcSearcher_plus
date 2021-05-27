import subprocess
from collections import defaultdict
import os
import re
import sys


class  finder(object):
	def __init__(self,func=None, addr=None):
		self.symbols={}
		self.libcbase=None
		self.__libc_path=os.path.join(os.path.realpath(os.path.dirname(__file__)), "../libc-database/db/")
		self.__fun_news=defaultdict(int)
		self.__check(func,addr)
		self.__search()
	
	def __check(self,func,addr):
		if  type(func)!= str:
			print("[+]wrong: func name not is string !")
			return None
		if  type(addr)!= int:
			print("[+]wrong: func address not is int !")
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
		
	def __search(self):
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
				print("[x]wrong: No matched, Make sure you supply a valid function name or just add more libc.")
				return None
			elif len(libcs)>1:
				print("multi libc results:")
				for x in range(len(libcs)):
					with open(os.path.join(self.__libc_path,libcs[0].rstrip('.symbols')+'.info'), 'r') as f:
						info=f.read().rstrip('\n')
					print("[-]%2d: %s(source from:%s)" % (x,libcs[x].rstrip('.symbols'),info))
				while True:
						try:						
							libcs_id = input("you can choose it by hand\nOr type 'exit' to quit:")
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
				
	def one_gadget(self,level=0):
		so_path=self.__libc_path.rstrip('.symbols')+'.so'
		if os.path.exists(so_path)==False:
			print("[x]wrong:don't find .so file")
			return None
		else:
			try:
				x=subprocess.check_output(["one_gadget","--level",str(level),so_path])
			
			except FileNotFoundError:
				print('find out one_gadget')
			
			else:
				oggtext=x.decode().split('\n\n')
				oggls=re.findall(r'0x[0-9A-F]+ ', x.decode(), re.I)
				for i in range(len(oggls)):
					print('[*]%2d: %s'%(i,oggtext[i]))
				while True:
					try:
						in_id = input("[!] you can choose a gadget by hand or type 'exit' to quit:")
					except:
						break
					if in_id == "exit" or in_id == "quit":
					    break
					try:
					    in_id = int(in_id)
					    oggls = int(oggls[in_id],16)
					    print('[*] you choose gadget: %s'%(hex(oggls)))
					    break
					except:
					    continue
				return oggls

if __name__ == "__main__":
	
	x=finder('write',0xf7eb4c90)
	x.one_gadget()
	print(x.dump('read'))
	print(x.libcbase)
	#print(x.__fun_news)
	#x.search()
