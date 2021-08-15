# Tednol's Docker Validator Guide

This guide presents a straightforward and focused guide to set up a production grade validator node on Radix using Docker.
It won't discuss all possible ways to set up a Docker node. It is intended to document my approach. The guide is tested and based on Ubuntu 20.04.

This is work in progress and some parts may change with the upcoming node releases.

This document draws heavily (and with kind permission) from the excellent resource Florian produced for standalone installs. https://github.com/fpieper/fpstaking/blob/main/docs/validator_guide.md

It does not match capabilities 1:1 with Florian's implementation especially with regards to failover. My failover approach has been tested repeatedly, but when it comes to failover time is of the essence and I suggest you practice my approach on Stokenet before seeking to deploy on mainnet. All the steps below apply to either mainnet or Stokenet, I'll be sure to highlight where there are differences to consider.

# Basic Setup

## Create User
Create a user which you use instead of root (pick your own username, I'm using radix). 
```
adduser radix
```

Add user to sudo group
```
adduser radix sudo
```

Change user and go to home directory
```
su - radix
```

Lock root password to disable root login via password
(don't confuse with `-d` it removes the password and allows to login without a password)
```
sudo passwd -l root
```

## Hostname

You may want to set a different hostname to make distinguishing between your different nodes easier e.g. mainnet-1, mainnet-2, stokenet-1, e.g.
```
sudo hostnamectl set-hostname mainnet-1
```

## SSH
Based on https://withblue.ink/2016/07/15/stop-ssh-brute-force-attempts.html

### Public Key Authentication
It is recommended to use ED25519 keys for SSH (same like Radix is using itself for signing transactions).
Generate a key with a strong passphrase to protect it on your CLIENT system.

On Linux:
```
ssh-keygen -t ed25519
```
On Windows PuTTYgen can be used to generate an ED25519 key.

On the `SERVER` paste your generated public key (in OpenSSH format) into `authorized_keys`:
```
mkdir -p ~/.ssh && nano ~/.ssh/authorized_keys
```

Remove all "group" and "other" permissions and ensure ownership of `.ssh` is correct:
```
chmod -R go= ~/.ssh
chown -R radix:radix ~/.ssh
```

Further details:
- https://medium.com/risan/upgrade-your-ssh-key-to-ed25519-c6e8d60d3c54
- https://www.digitalocean.com/community/tutorials/how-to-set-up-ssh-keys-on-ubuntu-20-04

### Secure Configuration
To secure SSH we:
 - Change the port (use your own custom port instead of `1234`).
   Though this doesn't really make your node more secure, but stops a lot of low effort 'attacks' appearing in your log files.
 - Disable password authentication
 - Disable root login
 - Only allow our own user `radix` to connect

Modify or add the following settings to `/etc/ssh/sshd_config`.
```
sudo nano /etc/ssh/sshd_config
```
Make these changes. The first three will already be in the config file, just remove the # at the start of the line (if there is one) and change the text. Add the final line to the bottom of the doc
```
Port 1234
PasswordAuthentication no
PermitRootLogin no
AllowUsers radix
```


### Restart SSH
To activate the changes restart the SSH service
```
sudo systemctl restart sshd
```

## Firewall
Docker, frutratingly, does not always abide by UFW firewall rules. Docker actually bypasses UFW and directly alters iptables, such that a container can bind to a port. This means that UFW rules you have set won't apply to Docker containers.

Personally, I have set UFW rules regardless. However this is not enough in isolation, I have mitigated the Docker limitation by setting up firewall rules with my hosting providers.

First, let's get UFW set-up. Ensure that safe defaults are set (they should be in a clean installation) 
```
sudo ufw default deny incoming
sudo ufw default allow outgoing
```

Second, we will only open the Radix network gossip on port 30000/tcp.
```
sudo ufw allow 30000/tcp
```
I strongly suggest you do not open your SSH port to all IP addresses. My own set up involves having a simple, secure, low cost admin server with a fixed IP that I can access from anywhere. I never SSH directly into the nodes, instead using a multi-hop connection via my admin server. My admin server serves only two purposes - it is a place on which to store my keystore files as backups, and accepts SSH connections from any IP address and is used for multi-hops into my actual nodes.

If you follow my advice, to open the SSH port only to a fixed IP, use replacing x.x.x.x with your fixed IP
```
sudo ufw allow from x.x.x.x to any port 1234
```
If you want to ignore my advice and open your SSH port from anywhere, instead run
```
sudo ufw allow 1234/tcp
```
You'll also need port 8080 open if you are planning on operation an archive node but that is outside scope of this guide.

Let's modify `/etc/ufw/before.rules` to stop the server responding to random ping requests to reduce the DDoS attack vectors
```
sudo nano /etc/ufw/before.rules
```
In this file, change the bit ~34 rows down from
```
# ok icmp codes for INPUT
-A ufw-before-input -p icmp --icmp-type destination-unreachable -j ACCEPT
-A ufw-before-input -p icmp --icmp-type source-quench -j ACCEPT
-A ufw-before-input -p icmp --icmp-type time-exceeded -j ACCEPT
-A ufw-before-input -p icmp --icmp-type parameter-problem -j ACCEPT
-A ufw-before-input -p icmp --icmp-type echo-request -j ACCEPT
```
to
```
# ok icmp codes for INPUT
-A ufw-before-input -p icmp --icmp-type destination-unreachable -j DROP
-A ufw-before-input -p icmp --icmp-type source-quench -j DROP
-A ufw-before-input -p icmp --icmp-type time-exceeded -j DROP
-A ufw-before-input -p icmp --icmp-type parameter-problem -j DROP
-A ufw-before-input -p icmp --icmp-type echo-request -j DROP
```
Next firewall thing to change, given we are doing a Docker install and Docker by default ignores the rules set in UFW, requires a change to the `/etc/ufw/after.rules` file

```
sudo nano /etc/ufw/after.rules
```
At the bottom of this file, add the following lines
```
# BEGIN UFW AND DOCKER
*filter
:ufw-user-forward - [0:0]
:ufw-docker-logging-deny - [0:0]
:DOCKER-USER - [0:0]
-A DOCKER-USER -j ufw-user-forward

-A DOCKER-USER -j RETURN -s 10.0.0.0/8
-A DOCKER-USER -j RETURN -s 172.16.0.0/12
-A DOCKER-USER -j RETURN -s 192.168.0.0/16

-A DOCKER-USER -p udp -m udp --sport 53 --dport 1024:65535 -j RETURN

-A DOCKER-USER -j ufw-docker-logging-deny -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -d 192.168.0.0/16
-A DOCKER-USER -j ufw-docker-logging-deny -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -d 10.0.0.0/8
-A DOCKER-USER -j ufw-docker-logging-deny -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -d 172.16.0.0/12
-A DOCKER-USER -j ufw-docker-logging-deny -p udp -m udp --dport 0:32767 -d 192.168.0.0/16
-A DOCKER-USER -j ufw-docker-logging-deny -p udp -m udp --dport 0:32767 -d 10.0.0.0/8
-A DOCKER-USER -j ufw-docker-logging-deny -p udp -m udp --dport 0:32767 -d 172.16.0.0/12

-A DOCKER-USER -j RETURN

-A ufw-docker-logging-deny -m limit --limit 3/min --limit-burst 10 -j LOG --log-prefix "[UFW DOCKER BLOCK] "
-A ufw-docker-logging-deny -j DROP

COMMIT
# END UFW AND DOCKER
```
Final bit of Docker firewall preparation is to run
```
sudo ufw route allow proto tcp from any to any port 30000
```
Afterwards we enable the firewall and check the status.
```
sudo ufw enable
sudo ufw status
```
Be careful and verify whether you can successfully open a new SSH connection before closing your existing session. Now after you ensured you didn't lock yourself out of your
server we can continue with setting up the Radix node itself.

## Linux kernal hardening
One relatively easy way to DDoS a Radix node is a SYN flood attack, https://en.wikipedia.org/wiki/SYN_flood

There are a few things we can change in the kernal to make our node more robust to these.

```
sudo nano /etc/sysctl.conf
```
In this file, find the `#net.ipv4.tcp_syncookies=1` row and remove the `#` from the beginning.
At the bottom of the file, add these two rows:
```
net.ipv4.tcp_max_syn_backlog=16384
net.ipv4.tcp_synack_retries=2
```
Finally to load these settings run:
```
sudo sysctl -p
```

## Update System
Update package repository and update system:
```
sudo apt update -y
sudo apt-get dist-upgrade
```

## Automatic system updates
We want automatic unattended security updates (based on https://help.ubuntu.com/community/AutomaticSecurityUpdates)
```
sudo apt install unattended-upgrades
sudo dpkg-reconfigure --priority=low unattended-upgrades
```

You can check whether it created the `/etc/apt/apt.conf.d/20auto-upgrades` file with the following content:
```
cat /etc/apt/apt.conf.d/20auto-upgrades
```
```
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
```

If you want to configure optional email notifications you can check out this article 
https://linoxide.com/enable-automatic-updates-on-ubuntu-20-04/.


## Kernel live patching
Kernel live patching is excellent because it means fewer restarts. We will use `canonical-livepatch` for kernel live patching.
First we need to check whether you are running the `linux-generic` kernel (or any of these `generic, lowlatency, aws, azure, oem, gcp, gke, gkeop, https://wiki.ubuntu.com/Kernel/Livepatch - then you can skip installing a different kernel and move to enabling `livepatch` directly).
```
uname -a
```

If you are not running linux-generic, you need to uninstall your current kernel
(replace `linux-image-5.4.0-1040-kvm` with your kernel version) and then install linux-generic:
https://www.reddit.com/r/Ubuntu/comments/7pujtv/difference_between_linuxgeneric_and_linuxkvm/
```
dpkg --list | grep linux-image
sudo apt-get remove --purge linux-image-5.4.0-1040-kvm
sudo apt install linux-generic
sudo update-grub
sudo reboot
```

Attach the machine to your Ubuntu account and activate livepatch (register for a token on https://ubuntu.com/security/livepatch)
```
sudo ua attach <your token>
sudo snap install canonical-livepatch
sudo ua enable livepatch
```

To reinstall your old kernel (if linux-kvm was previously used) - uninstall linux-generic kernel like above and then:
```
sudo apt install linux-kvm
```

Check for status
```
sudo canonical-livepatch status --verbose
```

Troubleshooting: maybe reinstalling the kernel if necessary
```
sudo apt-get install --reinstall linux-generic
```

## Shared Memory Read Only
Based on https://www.techrepublic.com/article/how-to-enable-secure-shared-memory-on-ubuntu-server/

Add the following line to your `/etc/fstab` file:
```
none /run/shm tmpfs defaults,ro 0 0
```

Enable changes
```
sudo mount -a
sudo reboot
```


# Radix Node
We install the Radix node using the CLI and the Docker Method: https://docs.radixdlt.com/main/node/cli-install.html. 


## Install the CLI tool
Download the latest version of the CLI tool. Check https://github.com/radixdlt/node-runner/releases, if there is a version > 1.0.4 you'll need to replace the link in the command to that version
```
wget -O radixnode https://github.com/radixdlt/node-runner/releases/download/1.0.4/radixnode-ubuntu-20.04
```
Make this downloaded file executable:
```
chmod +x radixnode
```
Move the file location so it is accessible from any other directory:
```
sudo mv radixnode /usr/local/bin
```


## Install Docker and the node
This is easy with the help of the CLI

```
radixnode docker configure
```
You will need to confirm a few times, and it takes a minute or so. Once this step has completed and returned you to the command line, logout of the SSH session and log back in.

When you are back in (if you made an error with your firewall and changing your SSH port, you'll definitely realise it at this point!), it's time to install the node.

But first you need to pick a seed. Choose one near to the location of your node from the list here: https://docs.radixdlt.com/main/node/cli-install-node-docker.html#_install_the_node
```
radixnode docker setup -n fullnode -t <ADDRESS & IP OF CHOSEN SEED>
```
Assuming you don't already have a node-keystore.ks, you'll be asked to create one. Enter a password and save this somewhere. You'll be asked to configure a location for the RADIXDB, my suggestion is /home/radix/RADIXDB but anywhere that works for you is fine

## Set passwords
Now it is time to set three passwords for the Nginx server. My suggestion is to choose 32 character passwords without symbols, and obviously they should be different for each password.

First up is the admin user and password for access to the Nginx server that was automatically installed in the previous step.
```
radixnode auth set-admin-password --setupmode DOCKER
```
Follow the prompts and set your password. Now we set that password as a variable, first replacing admin-nginx-password from the code below.
```
echo 'export NGINX_ADMIN_PASSWORD="admin-nginx-password"' >> ~/.bashrc
```

Next up is the superadmin user password. Almost the same as above but with the following commands
```
radixnode auth set-superadmin-password --setupmode DOCKER
```
Follow the prompts and set your password. Now we set that password as a variable, first replacing superadmin-nginx-password from the code below.
```
echo 'export NGINX_SUPERADMIN_PASSWORD="nginx-password"' >> ~/.bashrc
```

Lastly, assuming you want metrics (and you do), set the metrics password.
```
radixnode auth set-metrics-password -m DOCKER
```
Follow the prompts and set your password. Now we set that password as a variable, first replacing nginx-metrics-password from the code below.
```
echo 'export NGINX_METRICS_PASSWORD="nginx-metrics-password"' >> ~/.bashrc
```

Finally all all those environment variables to your current session with
```
source ~/.bashrc
```
# Monitoring
We are going to completely ignore the `radixnode monitoring setup` option, because we don't want to be running a webserver that is listening to the internet for connections.

Create a Grafana Cloud account at Grafana.com, it's free and awesome.

Go to https://<YourChosenIdName>.grafana.net/a/grafana-easystart-app/?selected=, click Linux server, then the Next button at the bottom.

Don't change any settings, the default options are good. Copy the install script and run it. We'll now be pushing server health data to Grafana Cloud, but we need to do some config for node health data.
 
Go into your default config file `sudo nano /etc/grafana-agent.yaml` and copy / paste it into a text editor.

Delete the config file
```
sudo rm /etc/grafana-agent.yaml
```
Recreate the config file
```
sudo nano /etc/grafana-agent.yaml
```
Replace the entire contents of the file with this. Don't change any of the spacing. Replace the <x>,<y> and <z>'s with the values in your default config file. Add the metrics password you set into <NGINX METRICS PASSWORD>, and fill in the items in <> and remove the <> brackets from the final file
```
integrations:
  node_exporter:
    enabled: true
  prometheus_remote_write:
  - basic_auth:
      password: <x>
      username: <y>
    url: https://prometheus-blocks-prod-us-central1.grafana.net/api/prom/push
loki:
  configs:
  - clients:
    - basic_auth:
        password: <x>
        username: <z>
      url: https://logs-prod-us-central1.grafana.net/api/prom/push
    name: integrations
    positions:
      filename: /tmp/positions.yaml
    target_config:
      sync_period: 10s
prometheus:
  configs:
  -   name: integrations
      scrape_configs:
      - basic_auth:
            password: <NGINX METRICS PASSWORD>
            username: metrics
        job_name: radix_fullnode
        metrics_path: /metrics
        scheme: https
        static_configs:
        -   labels:
                network: <mainnet>
                node: <radup1>
                public_ip: <x.x.x.x>
            targets:
            - localhost
        tls_config:
            insecure_skip_verify: true
      remote_write:
      -   basic_auth:
              password: <x>
              username: <y>
          url: https://prometheus-blocks-prod-us-central1.grafana.net/api/prom/push
  global:
    scrape_interval: 15s
  wal_directory: /tmp/grafana-agent-wal
server:
  http_listen_port: 12345
```
Exit and save and restart Grafana Agent
```
sudo systemctl restart grafana-agent.service
```
Run this to check for error messages, hopefully it looks good.
```
sudo systemctl status grafana-agent.service
```

## Bringing up the node for the first time
You've actually already used this command when you first installed the node. Remember again to customise this command based on your choosen seed.
```
radixnode docker setup -n fullnode -t <ADDRESS & IP OF CHOSEN SEED>
```
Enter the password for the node-keystore.ks you set previously, and set the same RADIXDB location.

All being well your node is now running and synchronising. Check by running
```
radixnode api account get-info
```
In the information that is returned you should see a result that includes the address of the node (starting rdx1)

```
radixnode api health
```

This returns the current status of the node. It should say "SYNCING" which means it is running ok and currently synchronising. It will eventually changed to "UP" after full syncronisation but you don't need to wait for this to contiue with the steps.

You can also check out our dashboard on Grafana Cloud. https://radup.grafana.net/d/RO9kC7Gnz/radix-node-dashboard-default?orgId=1&refresh=10s. The new node name (e.g. Mainnet-1 or whatever you have called it) will hopefully be an option you can select top left. As if by magic you should see some data in the dashboard. Might not be complete, but will be in a few minutes!


## Optimise the node
Run
```
sudo radixnode optimise-node
sudo apt install ansible
```
Logout and log back in again. Then re-run
```
sudo radixnode optimise-node
```
Answer Y to prompts, and 8G for the swap file
 
# Useful commands
Check node version:
```
radixnode api version
```
Check node health
```
radixnode api health
```
Get node info:
```
radixnode api account get-info
```
Register as a validator / change fees / names / URL etc
```
radixnode api account update-validator-config
```
Show validator node details:
```
radixnode api validation get-node-info
```
Check metrics:
```
curl -u metrics:<METRICS PASSWORD> -k "https://localhost/metrics"
```
Who has staked
```
radixnode api validation get-node-info
```

