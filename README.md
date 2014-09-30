## Crowbar (Levye) - Brute forcing tool for pentests


### What is it?

**Crowbar** (crowbar) is brute forcing tool that can be used during penetration tests. It is developed to support protocols that are not currently supported by thc-hydra and other popular brute forcing tools. 

Currently **Crowbar** supports  
- OpenVPN
- SSH private key authentication
+ VNC key authentication
* Remote Desktop Protocol (RDP) with NLA support

### Installation

First you shoud install dependencies
```
 # apt-get install openvpn freerdp-x11 vncviewer ssh 
```

Then get latest version from github  
```
 # git clone https://github.com/galkan/crowbar 
```

Attention: Rdp depends on your Kali version. It may be xfreerdp for the latest version.

### Usage

**Brute forcing RDP**  
```
 # ./crowbar.py -b rdp -s 172.16.1.12/32 -u Administrator -c pass.txt  
```

**Brute forcing SSH**  
```
# ./crowbar.py -b sshkey -s 127.0.0.1/32 -u root -p 22 -k id_rsa  
```

**Brute forcing VNC server**  
```
# ./crowbar.py -b vnckey -s 172.16.3.87/32 -p 5901 -c keys/vncpass  
```

**Brute forcing OpenVPN**  
```
# ./crowbar.py -b openvpn -s 172.16.1.100/32 -m server.ovpn -c pass.txt -u user.txt -k server.ca.crt -p 443  
```

### Example Output

 Once you have executed crowbar, it generates 2 files for logging and result. Default log file name is crowbar.log which is    
 located in your current directory.  

 # cat crowbar.out 


