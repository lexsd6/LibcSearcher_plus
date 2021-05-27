## 简介

项目[LibcSearcher](https://github.com/lieanu/LibcSearcher)项目所启发优化而来的项目。为解决LibcSearcher使用过程琐杂，在写沉余重复代码浪费时间的问题。优化代码部分逻辑，使在使用更便捷的基础上，添加one_gatge查询功能。

## 安装

喜欢手动的师傅执行下面命令即可:

```shell
sudo git clone https://github.com/lexsd6/LibcSearcher_plus.git
cd ./LibcSearcher_plus
sudo chmod 777 ./setup.py #远程仓库文件权限问题
sudo git clone https://github.com/niklasb/libc-database.git
sudo apt-get install ruby2.6 ruby2.6-dev  #有ruby环境可以跳过
sudo gem install one_gadget
sudo ./setup.py develop
```

当然也可以执行文件中`./create`脚本文件来代替操作:

```shell
sudo git clone https://github.com/lexsd6/LibcSearcher_plus.git
cd ./LibcSearcher_plus
sudo chmod 777 ./create
sudo ./create
```

执行`from libcfind import *`或`import  libcfind`无报错则成功。

## 项目特性

### 加载与查询库

与[LibcSearcher](https://github.com/lieanu/LibcSearcher)项目类似，我们可以用`from *** import *`方法来载入：

```python
from libcfind import *

x=finder('write',0xf7eb4c90) #finder(函数名,函数地址)来查找数据库
```

同时我们也可以按传统`import`方式载入：

```python
import libcfind

x=libcfind.finder('write',0xf7eb4c90) #libcfind.finder(函数名,函数地址)来查找数据库
```

同时在查找时，面对由多种情况时保留了[LibcSearcher](https://github.com/lieanu/LibcSearcher)的手动输入特色：

```shell
multi libc results:
[-] 0: libc6-amd64_2.27-3ubuntu1_i386(source from:ubuntu-glibc)
[-] 1: libc6-amd64_2.27-3ubuntu1.2_i386(source from:ubuntu-glibc)
[-] 2: libc6_2.27-3ubuntu1.4_amd64(source from:ubuntu-glibc)
[-] 3: libc6_2.27-3ubuntu1_amd64(source from:ubuntu-glibc)
[-] 4: libc6_2.27-3ubuntu1.2_amd64(source from:ubuntu-glibc)
[-] 5: local-426a1bd5fe73ff6ac6dc17213ab10ff67f3b7193(source from:ubuntu-glibc)
[-] 6: libc6-amd64_2.27-3ubuntu1.4_i386(source from:ubuntu-glibc)
you can choose it by hand
Or type 'exit' to quit:5
[+] local-426a1bd5fe73ff6ac6dc17213ab10ff67f3b7193 baseaddr=0x7f400e8e2000 (source from:/glibc/2.27/amd64/lib/libc-2.27.so)
```

同时在选定库后会显示这时libc的基地址。

### 地址查询

```python
baseaddr=x.libcbase   #所得这时libc的基地址
libc_read=x.symbols['read']   #获得read函数在libc中的偏移
real_read=x.dump('read')  #获得read函数真实地址（基地址+libc中的偏移）
#同理
libc_system=x.symbols['system']   #获得system函数在libc中的偏移
libc__malloc_hook=x.symbols['__malloc_hook']   #获得__malloc_hook在libc中的偏移
real_str_bin_sh=x.dump('str_bin_sh')  #获得‘/bin/sh’真实地址（基地址+libc中的偏移）
real_libc_start_main_ret=x.dump('__libc_start_main_ret')  #获得__libc_start_main_ret真实地址（基地址+libc中的偏移）
```



### one_gadget查询

依赖[one_gadget](https://github.com/david942j/one_gadget)项目的简单one_gadget的偏移查询,返回结果one_gadget的真实地址(基地址+libc中的偏移)

```python
x.one_gadget()#即可查询
x.one_gadget(1) #设置查询等级，即 one_gadget --level 1
```

有多个one_gadget，会如下提示，手动选择。

```python
[*] 0: 0x3ac6c execve("/bin/sh", esp+0x28, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x28] == NULL
[*] 1: 0x3ac6e execve("/bin/sh", esp+0x2c, environ)
constraints:
  esi is the GOT add
ress of libc
  [esp+0x2c] == NULL
[*] 2: 0x3ac72 execve("/bin/sh", esp+0x30, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x30] == NULL
[*] 3: 0x3ac79 execve("/bin/sh", esp+0x34, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x34] == NULL
[*] 4: 0x5fbd5 execl("/bin/sh", eax)
constraints:
  esi is the GOT address of libc
  eax == NULL
[*] 5: 0x5fbd6 execl("/bin/sh", [esp])
constraints:
  esi is the GOT address of libc
  [esp] == NULL

[!] you can choose a gadget by hand or type 'exit' to quit:5
[*] you choose gadget: 0x5fbd6
```


## 其他

本人技术水平一般，代码功底很差，如有缺陷与不足欢迎提出与吐槽。
