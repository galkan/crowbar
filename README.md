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
 # apt-get install openvpn freerdp-x11 vncviewer
```

Then get latest version from github  
```
 # git clone https://github.com/galkan/crowbar 
```

Attention: Rdp depends on your Kali version. It may be xfreerdp for the latest version.

### Usage

**-h**: Shows help menu.

**-b**: Target service. Crowbar now supports vnckey, openvpn, sshkey, rdp.

**-s**: Target ip address.

**-S**: File name which is stores target ip address.

**-u**: Username.

**-U**: File name which stores username.

**-n**: Thread count.

**-l**: File name which stores log. Deafault file name is crwobar.log which is located in your current directory

**-o**: Output file name which stores the successfully attempt.

**-c**: Password.

**-C**: File name which stores passwords.

**-t**: Timeout value.

**-p**: Port number 

**-k**: Key file full path. 

**-m**: Openvpn configuration file path

**-d**: Run nmap in order to discover whether the target port is open or not. So that you can easily brute to target using crowbar. 

**-v**: Verbose mode which is shows all the attempts including fail.


If you want see all usage options, please use **crowbar --help** 

![alt tag](https://raw.githubusercontent.com/galkan/crowbar/master/images/crowbar-parola-dosyasi.jpg) 


**Brute forcing RDP**  

Below are the examples which you have options for using crowbar. 

```
crowbar.py -b rdp -s 192.168.2.182/32 -u admin -c Aa123456
```
![alt tag](https://raw.githubusercontent.com/galkan/crowbar/master/images/crowbar-rdp.jpg)

```
crowbar.py -b rdp -s 192.168.2.211/32 -U /root/Desktop/userlist -c passw0rd
```
![alt tag](https://raw.githubusercontent.com/galkan/crowbar/master/images/crowvar-rdp-dosya.jpg)

```
crowbar.py -b rdp -s 192.168.2.250/32 -u localuser -C /root/Desktop/passlist
```
![alt tag](https://raw.githubusercontent.com/galkan/crowbar/master/images/crowvar-rdp-dosya2.jpg)

```
crowbar.py -b rdp -s 192.168.2.0/24 -U /root/Desktop/userlist -C /root/Desktop/passlist -d
```
![alt tag](https://raw.githubusercontent.com/galkan/crowbar/master/images/crowvar-rdp-kadi-parola-dosya.jpg)


**Brute forcing SSH**  

Below are the examples which you have options for using crowbar.

```
crowbar.py -b sshkey -s 192.168.2.105/32 -u root -k /root/.ssh/id_rsa
```
![alt tag](https://raw.githubusercontent.com/galkan/crowbar/master/images/crowbar-ssh1.jpg)

```
crowbar.py -b sshkey -s 192.168.2.105/32 -u root -k /root/.ssh/
```
![alt tag](https://raw.githubusercontent.com/galkan/crowbar/master/images/crowbar-ssh2.jpg)


```
crowbar.py -b sshkey -s 192.168.2.0/24 -u root -k /root/.ssh/ -d
```
![alt tag](https://raw.githubusercontent.com/galkan/crowbar/master/images/crowbar-ssh3.jpg)

Attention: If you want, you can specify the key directory with -k option. Crowbar will use all the files under this directory for brute force. For instance;

``# crowbar.py -k /root/.ssh``


**Brute forcing VNC server**  

Below is the example which you have options for using crowbar.

```
crowbar.py -b vnckey -s 192.168.2.105/32 -p 5902 -c /root/.vnc/passwd 
```
![alt tag](https://raw.githubusercontent.com/galkan/crowbar/master/images/crowbar-vnc.jpg)


**Brute forcing OpenVPN**  

Below are the example which you have options for using crowbar.

```
crowbar.py -b openvpn -s 198.7.62.204/32 -p 443 -m /root/Desktop/vpnbook.ovpn -k /root/Desktop/vpnbook_ca.crt -u vpnbook -c cr2hudaF
```
![alt tag](https://raw.githubusercontent.com/galkan/crowbar/master/images/crowbar-vpn.jpg)


### Example Output

 Once you have executed crowbar, it generates 2 files for logging and result. Default log file name is crowbar.log which is    
 located in your current directory. If you don't want use default log file, you should use -l log_path. After that you can   
 observe crowbar operations. Please look at the crowbar.log and crowbar. file 

#### Thanks To
 
 - Bahtiyar Bircan
 - Ertuğrul Başaranoğlu
