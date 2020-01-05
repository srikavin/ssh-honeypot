# SSH Honeypot

This honeypot logs ips, username, and passwords from connections made to the server.

## Installation
*Before beginning, make sure to reconfigure sshd to listen on another port.*

1. `sudo dnf -y install libssh-devel`
2. `git clone https://github.com/srikavin/ssh-honeypot`
3. `cd ssh-honeypot`
4. `make`
5. `sudo ./ssh_honeypot 22 /etc/ssh/ssh_host_rsa_key credentialLog.txt ipLog.txt`

