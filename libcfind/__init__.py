# -*- coding: utf-8 -*-
"""
Created on Mon Jul 19 21:11:32 2025

@author: lexsd6
"""

import difflib
import subprocess
from collections import defaultdict
import os
import re
import sys
from psutil._compat import FileNotFoundError
import libcfind.libc_symbols as libc_symbols
from elftools.elf.elffile import ELFFile




class  finder(object):
	def __init__(self,func=None, addr=None,num=None,path=None):
		"""[summary]
			Using  function name and  really addr to find remote environment libc.so

		Args:
			func ([string]): Function name to query.
			addr ([int]): The real address of the function to query.
			num ([int], optional): Select results,you can select results directly instead of manually . Defaults to None.
		"""
		self.symbols={}
		"""
			[summary]
			libc symbols addrs
		"""
		self.libcbase=0
		"""
			[summary]libc's base addr 
		"""
		
		self.__fun_news=defaultdict(int)
		self.__check(func,addr)
		if path ==None:
			self.__libc_path=os.path.normpath(os.path.join(os.path.realpath(os.path.dirname(__file__)), "../libc-database/db/"))
			self.__search(num)
		else:
			self.__libc_path=os.path.normpath(path)
			self.__local_libc(path)
	def __wrong(self):
		if hasattr(__import__('__main__'), '__file__'):
			sys.exit(0)
		
		return None

	
	def __check(self,func,addr):
		if  type(func)!= str:
			print("[\033[0;31;1mx\033[0m] wrong: func name not is string !")
			return self.__wrong()
		if  type(addr)!= int:
			print("[\033[0;31;1mx\033[0m] wrong: func address not is int !")
			return self.__wrong()
		self.__fun_news['func']=func
		self.__fun_news['addr']=addr
		
	def __bind(self,libcsname):
		with open(self.__libc_path, 'r') as f:
			self.symbols=dict([i.strip('\n').split(' ')[0],int(i.strip('\n').split(' ')[-1],16)] for i in f.readlines())			
		self.libcbase=self.__fun_news['addr']-self.symbols[self.__fun_news['func']]
	def __local_libc(self,path):
		with open(path, 'rb') as f:
			elffile = ELFFile(f)
        
			
			symtab = elffile.get_section_by_name('.symtab')  
			dynsym = elffile.get_section_by_name('.dynsym')  
			
			
			for sym_section in [symtab, dynsym]:
			    if sym_section is None:
			    	continue
				
			    
			    strtab_index = sym_section['sh_link']
			    strtab = elffile.get_section(strtab_index)
			    
			    
			    for sym in sym_section.iter_symbols():
			    	if sym['st_name'] == 0:
			    		continue
			    	try:
			    		name = strtab.get_string(sym['st_name'])
			    	except UnicodeDecodeError:
			    		continue
			    	self.symbols[name] = sym['st_value']

			
			self.libcbase=self.__fun_news['addr']-self.symbols[self.__fun_news['func']]
			print("[\033[0;32;1m+\033[0m] loading \033[0;34;1m%s\033[0m \033[0;31;1mbaseaddr: %s\033[0m (source from:\033[0;33;1m%s\033[0m)" % (path,hex(self.libcbase),'local'))
	def dump(self,func):
		"""[summary]

		Args:
			func (str): function or symbol name 

		Returns:
			[int]: function or symbol really addr( symbol's addr + libc's base addr)
		"""
		if self.libcbase:
			try:	
				funcaddr=self.libcbase+self.symbols[func]
				print('[\033[0;32;1m+\033[0m] %s:\033[0;32;1m%s\033[0m'%(func,hex(funcaddr)))
				return funcaddr
			except:
				mean=difflib.get_close_matches(func,self.symbols,12,0.4)
				if len(mean)==0:
					print("[\033[0;31;1mx\033[0m] wrong:don't find '\033[0;31;1m%s\033[0m' in libc！"%(func))
				else:
					print("[\033[0;31;1mx\033[0m] wrong:No symbol '\033[0;31;1m%s\033[0m' found in libc！did you mean:"%(func))
					print(mean)
				return self.__wrong()
					
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
				fnamekeys=libc_symbols.default_libc_symbols
				if fnamekeys.count(self.__fun_news['func'])==0:
					mean=difflib.get_close_matches(self.__fun_news['func'],fnamekeys,12,0.4)
				else:
					mean=[]
				if len(mean)==0:
					print("[\033[0;31;1mx\033[0m] wrong: No matched, Make sure you supply a valid function name or add more libc in \033[0;31;1m %s\033[0m"%(self.__libc_path))
					return self.__wrong()
				else :
					print("[\033[0;31;1mx\033[0m] wrong: No matched, Make sure you supply a valid function name ,may you mean:")
					print(mean)
					print("or add more libc in \033[0;31;1m %s\033[0m"%(self.__libc_path))
					return self.__wrong()
			elif len(libcs)>1:
				
					print("[\033[0;32;1m*\033[0m]multi libc results:")
					for x in range(len(libcs)):
						with open(os.path.join(self.__libc_path,libcs[x].rstrip('symbols')+'info'), 'r') as f:
							info=f.read().rstrip('\n')
						print("[-]%2d: \033[0;34;1m%s\033[0m (source from:\033[0;33;1m%s\033[0m)" % (x,libcs[x].rstrip('symbols')[:-1],info))
					
					while True:
								try:	
									if num==None:					
										libcs_id = input("[\033[0;33;1m!\033[0m] you can choose it by hand\nOr type 'exit' to quit:")
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
										self.so_path=self.__libc_path.rstrip('symbols')[:-1]+'.so'
										with open(self.__libc_path.rstrip('symbols')+'info', 'r') as f:
											info=f.read().rstrip('\n')
											print("[\033[0;32;1m+\033[0m] choosing \033[0;34;1m%s\033[0m \033[0;31;1mbaseaddr: %s\033[0m (source from:\033[0;33;1m%s\033[0m)" % (libcs.rstrip('symbols')[:-1],hex(self.libcbase),info))
										break
									except:
											continue		
			else :
				libcs=libcs[0]
				self.__libc_path=os.path.join(self.__libc_path,libcs)
				self.__bind(libcs)
				self.so_path=self.__libc_path.rstrip('symbols')[:-1]+'.so'
				
				with open(self.__libc_path.rstrip('symbols')+'info', 'r') as f:
						info=f.read().rstrip('\n')
				print("[\033[0;32;1m+\033[0m] choosing \033[0;34;1m%s\033[0m \033[0;31;1mbaseaddr: %s\033[0m (source from:\033[0;33;1m%s\033[0m)" % (libcs.rstrip('symbols')[:-1],hex(self.libcbase),info))
				
	def ogg(self,level=0,num=None):
		"""[summary]

		Args:
			level (int, optional): chese one_gadget level. Defaults to 0.
			num (int, optional): Select results,you can select results directly instead of manually . Defaults to None.

		Returns:
			[int]: one_gadget really addr(one_gadget result + libc's base addr)
		"""
		so_path=self.__libc_path.rstrip('symbols')[:-1] #+'.so'
		if  so_path.endswith('.so')==False:
			so_path+='.so'
		print(so_path)

		if os.path.exists(so_path)==False:
			print("[\033[0;31;1mx\033[0m] wrong:don't find .so file in \033[0;31;1m %s\033[0m"%(self.__libc_path))
			return self.__wrong()
		else:
			try:
				x=subprocess.check_output(["one_gadget","--level",str(level),so_path])
			
			except FileNotFoundError:
				print('[\033[0;31;1mx\033[0m] wrong:find out one_gadget')
				return self.__wrong()
			else:
				oggtext=x.decode().split('\n\n')
				oggls=re.findall(r'0x[0-9A-F]+ e', x.decode(), re.I)
				print("[\033[0;32;1m*\033[0m] multi one_gadget results:")
				if len(oggls)!=len(oggtext):
					print("[\033[0;31;1mx\033[0m] wrong: special libc ,please one_gadget by hand !")
				for i in range(len(oggls)):
					print('[-]%2d: \033[0;32;1m%s\033[0m %s'%(i,oggls[i][:-1],oggtext[i][len(oggls[i])-1:]))
				while True:
					try:
						if num==None:
							in_id = input("[\033[0;33;1m!\033[0m] you can choose a gadget by hand or type 'exit' to quit:")
							in_id = int(in_id)
						else :
							in_id=num
							num=None
					except:
						break
					if in_id == "exit" or in_id == "quit":
					    break
					try:
					    
					    oggls = int(oggls[in_id][:-1],16)
					    print('[\033[0;32;1m+\033[0m] you choose gadget: \033[0;32;1m%s\033[0m'%(hex(oggls)))
					    break
					except:
					    continue
				return oggls+self.libcbase



if __name__ == "__main__":
	
	x=finder('write',0xf7eb4c90)
	x.ogg(num=0)
	#x.ogg(num=11)
	print(x.dump('read'))
	print(x.libcbase)
	print(x.symbols['read'])
	#test('x')
	#x.search()
