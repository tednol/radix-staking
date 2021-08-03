# Production-grade Docker Validator Guide

This guide presents a straightforward and focused guide to set up a production grade validator node on Radix using Docker.
It won't discuss all possible ways to set up a Docker node. It is intended to document my approach. The guide is tested and based on Ubuntu 20.04.

This is work in progress and some parts may change with the upcoming node releases.

This document draws heavily (and with kind permission) from the excellent resource Florian produced for standalone installs. https://github.com/fpieper/fpstaking/blob/main/docs/validator_guide.md

It does not match capabilities 1:1 with Florian's implementation.

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

You may want to set a different hostname to make distinguishing between your different nodes easier e.g.:
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

Second, we will only allow the custom SSH port and Radix network gossip on port 30000/tcp.
```
sudo ufw allow 1234/tcp
sudo ufw allow 30000/tcp
```

You'll also need port 8080 open if you are planning on operation an archive node but that is outside scope of this guide.

Afterwards we enable the firewall and check the status.
```
sudo ufw enable
sudo ufw status
```

Be careful and verify whether you can successfully open a new SSH connection before
closing your existing session. Now after you ensured you didn't lock yourself out of your
server we can continue with setting up the Radix node itself.

Secondly, given Docker does not always abide by UFW rules, you will need to ensure your chosen hosting provider offers you a customisable firewall.
Config will vary across different cloud providers.
You will need to open the same tcp ports as you have opened on UFW. Config appropriately using support resources from your hosting provider if required.
From personal experience, setup is very self-explanatory across DigitalOcean, Linode and Vultr.

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
We will use `canonical-livepatch` for kernel live patching.
First we need to check whether you are running the `linux-generic` kernel
(or any of these `generic, lowlatency, aws, azure, oem, gcp, gke, gkeop`
https://wiki.ubuntu.com/Kernel/Livepatch - then you can skip installing a different kernel
and move to enabling `livepatch` directly).
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
Download the latest version of the CLI tool. You will need to replace LOCATION and the brackets below with the location of the 'radixnode-ubuntu-20.04' file marked as being the latest release here: https://github.com/radixdlt/node-runner/releases
```
wget -O radixnode <LOCATION>
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
You will need to confirm a few times, answer Y to proceed. At the end, exit out of your SSH connection and connect back in


## Set passwords
Now it is time to set three passwords for the Nginx server. My suggestion is to choose 32 character passwords without symbols.

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

## Bringing up the node for the first time
You've actually already used this command when you first installed the node. Remember again to customise this command based on your choosen seed.
```
radixnode docker setup -n fullnode -t <ADDRESS & IP OF CHOSEN SEED>
```

All being well your node is now running and synchronising. Check by running
```
radixnode api account get-info
```
In the information that is returned you should see a result that includes the address of the node (starting rdx1)

```
radixnode api health
```

This returns the current status of the node. It should say "SYNCING" which means it is running and currently synchronising. It will eventually changed to "UP" after full syncronisation.

## Optimise the node
COMING SOON

## Failover
COMING SOON

## Monitoring
I do not use the monitoring solution which is built into the CLI. The CLI monitoring solution is explained at https://docs.radixdlt.com/main/node/install-grafana-dashboard.html

There is nothing wrong with this option, however my preference is not to run a webserver on the same server as my node. If this option is one you want to explore, just bear in mind you will also need to open port 3000 on both UFW and your hosting provider customisable firewall.

If the CLI method works for you then stop here. Otherwise continue to read about how to integrate with Grafana Cloud.

I can recommend watching this comprehensive introduction to Grafana Cloud
https://grafana.com/go/webinar/intro-to-prometheus-and-grafana/.
First, sign up for a Grafana Cloud free account and follow their quickstart introductions to install
Grafana Agent on your node (via the automatic setup script). This basic setup is out of the scope of this guide.
You can find the quickstart introductions to install the Grafana Agent under
`Onboarding (lightning icon) / Walkthrough / Linux Server` and click on `Next: Configure Service`.
The Grafana Agent is basically a stripped down Promotheus which is directly writing to Grafana Cloud instead of storing metrics locally
(Grafana Agent behaves like having a built-in Promotheus). 
You should now have a working monitoring of your system load pushed to Grafana Cloud.

However it won't be pushing your node data to Grafana Cloud by default. 

## Extending Grafana Agent Config
Add the `scrape_configs` configuration to `etc/grafana-agent.yaml`: 
```
sudo nano /etc/grafana-agent.yaml
```
```
prometheus:
configs:
- name: integrations
  scrape_configs:
    - job_name: radix-mainnet-fullnode
      static_configs:
        - targets: ['localhost:3333']
  remote_write:
    - basic_auth:
      password: secret
      username: 123456
      url: https://prometheus-blocks-prod-us-central1.grafana.net/api/prom/push
```

The prefixes like `radix-mainnet` before `fullnode` or `validator` are arbitrary and can be used
to have two dashboards (one for mainnet and one for stokenet) in the same Grafana Cloud account.

Just set the template variable `job` to `radix-mainnet-validator` in your mainnet dashboard
and `radix-stokenet-validator` in your stokenet dashboard.

The switch-mode script replaces `fullnode` with `validator` and vice versa.
Set `job_name` in the config above to e.g. `radix-mainnet-fullnode` if you are running in fullnode mode and
`radix-mainnet-validator` if you are running as validator.

And restart to activate the new settings:
```
sudo systemctl restart grafana-agent
```

## Radix Dashboard

I adapted the official `Radix Node Dashboard`
https://github.com/radixdlt/node-runner/blob/main/monitoring/grafana/provisioning/dashboards/sample-node-dashboard.json
and modified it a bit for usage in Grafana Cloud (including specific job names for `radix-validator` and `radix-fullnode` for failover).
You can get the `dashboard.json` from https://github.com/fpieper/fpstaking/blob/main/docs/config/dashboard.json.
You only need to replace `<your grafana cloud name>` with your own cloud name
(three times, since it seems the alerts have problems to process a datasource template variable).
It is a good idea to replace the values and variables in your JSON and then import the JSON as dashboard into Grafana Cloud.

## Alerts

### Spike.sh for phone calls
To get phone proper notifications via phone calls in case of Grafana Alerts I am using Spike.sh.
It only costs 7$/month and is working great.
How you can configure Spike.sh as `Notification Channel` is described here:
https://docs.spike.sh/integrations-guideline/integrate-spike-with-grafana.
Afterwards you can select `Spike.sh` in your alert configurations.

### Grafana Alerts
You can find the alerts by clicking on the panel title / Edit / Alert.

I set an alert on the proposals made panel, which fires an alert if no proposal was made in the last 2 minutes.
However, this needs a bit tuning for real world condition (worked fine in betanet conditions).

You also need to set `Notifications` to `Spike.sh` (if you configured the `Notification Channel` above).
Or any other notification channel if you prefer `PagerDuty` or `Telegram`.

# More Hardening
## SSH
- https://serverfault.com/questions/275669/ssh-sshd-how-do-i-set-max-login-attempts  
- Restrict access to the port:
    - use a VPN
    - only allow connections from a fix IP address
      ```
      sudo ufw allow from 1.2.3.4 to any port ssh
      ```

## Restrict Local Access (TTY1, etc)
We can additionally restrict local access.
However, this obviously leads results in that you won't be able to login without SSH in emergencies.
(booting into recovery mode works with most virtual servers, but causes downtime).
But since we have multiple backup servers this can be a fair trade-off.

Uncomment or add in this file
```
sudo nano /etc/pam.d/login
```
the following line:
```
account required pam_access.so
```

Then uncomment or add in this file
```
sudo nano /etc/security/access.conf
```
the following line:
```
-:ALL:ALL
```

For further details:
- https://linuxconfig.org/how-to-restrict-users-access-on-a-linux-machine

# Logs & Status

Shows radix node logs with colours:
```
sudo journalctl -f -u radixdlt-node --output=cat
```

Shows node health (`BOOTING`, `SYNCING`, `UP`, `STALLED`, `OUT_OF_SYNC`)
```
curl -s localhost:3333/health | jq
```

Show account information:
```
curl -s -d '{ "jsonrpc": "2.0", "method": "account.get_info", "params": [], "id":1}' -H "Content-Type: application/json" -X POST "http://localhost:3333/account" | jq
```

Show node information:
```
curl -s -d '{"jsonrpc": "2.0", "method": "validation.get_node_info", "params": [], "id": 1}' -H "Content-Type: application/json" -X POST "http://localhost:3333/validation" | jq
```

Shows `targetStateVersion` (versions are kind of Radix's blocks in Olympia - how many blocks are synced):
```
curl -s -X POST 'http://localhost:3333/system' -d '{"jsonrpc": "2.0", "method": "sync.get_data", "params": [], "id": 1}' | jq ".result.targetStateVersion"
```

Shows the difference sync difference to the network.
Should be `0` if the node is fully synced (if `targetCurrentDiff` isn't `0`)
```
curl -s -X POST 'http://localhost:3333/system' -d '{"jsonrpc": "2.0", "method": "sync.get_data", "params": [], "id": 1}' | jq
```

Shows current validator information:
```
curl -s -d '{"jsonrpc": "2.0", "method": "validation.get_node_info", "params": [], "id": 1}' -H "Content-Type: application/json" -X POST "http://localhost:3333/validation" | jq
```

Get network peers:
```
curl -s -d '{"jsonrpc": "2.0", "method": "networking.get_peers", "params": [], "id": 1}' -H "Content-Type: application/json" -X POST "http://localhost:3333/system" | jq
```

Get network configuration:
```
curl -s -d '{"jsonrpc": "2.0", "method": "networking.get_configuration", "params": [], "id": 1}' -H "Content-Type: application/json" -X POST "http://localhost:3333/system" | jq
```
