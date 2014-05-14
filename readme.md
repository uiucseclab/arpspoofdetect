ARP Spoof Detect
=========

ARP Spoof Detect is a simple, lightweight ARP spoofing detector script that checks if your network is being ARP spoofed.

The script is easy to set up and safe to run in background. Once an ARP spoof attack is detected, a system notification will be sent to the user, and corresponding information will be logged in the log file.

![Alt text](/Screenshots/script_running.png?raw=true "ARP Spoof Detect is running normally.")
![Alt text](/Screenshots/system_notif1.png?raw=true "Mac Notification Center")
![Alt text](/Screenshots/system_notif2.png?raw=true "Mac PopUp Notification")

Features
----
  - Detect ARP reply messages in the network.
  - Detect if a machine has launched ARP spoof attack in the network.
  - Log all ARP reply messages and potential ARP spoof attacks in the log file.
  - Send system notification to user once such attack occurs. (Currently only supported in Mac OS X)

Dependencies
-----------
ARP Spoof Detect requires the following two packages to function on any machines.

* [Scapy] - Powerful packet manipulation package.
* [Netifaces] - Python network interface reader.

On Ubuntu machine, it is easy to install these two packages by doing
```
apt-get install python-scapy python-netifaces
```
On Mac OS X, use pip to install scapy and netifaces.

How To Run
----
First make sure detect_arpspoof.py is executable. Otherwise run
```
chmod +x detect_arpspoof.py
./detect_arpspoof.py
```
or simply you can just run
```
python detect_arpspoof.py
```
Please make sure that the script is run as the root user, as root privilege is required to operate network interfaces.

Now, choose the location where you wish to store your log file, or press enter to use the default file name. 

```
Please input desired log file name. [spoof.log]
```

Once you've selected the log file location, you will be prompted to choose the network interface on which you would like to detect ARP spoofing. For most cases, this should be the default network interface you use to access Internet. A list of available interfaces on your machine is offered for your convenience.

```
Please select the interface you wish to use. ['lo0', 'gif0', 'stf0', 'en0', 'en1', 'en2', 'bridge0', 'p2p0', 'vnic0', 'vnic1']
```

Once proper interfaces is selected, and no other error occurs, you will see
```
ARP Spoofing Detection Started. Any output is redirected to log file.
```

If you are running Mac OS X, when an ARP spoofing attack is in the network, you will receive a system notification alerting you to take proper actions. Otherwise, the attack will be logged in the log file. You may implement a listener that watches the file for the attack, should you need a realtime notification. 

[Scapy]:http://www.secdev.org/projects/scapy/
[Netifaces]:https://pypi.python.org/pypi/netifaces