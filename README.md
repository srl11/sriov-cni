   * [SR-IOV CNI plugin](#sr-iov-cni-plugin)
   	  * [changes](#change)	 
      * [Build](#build)
      * [Enable SR-IOV](#enable-sr-iov)
      * [Configuration reference](#configuration-reference)
         * [Main parameters](#main-parameters)
         * [Using DPDK drivers:](#using-dpdk-drivers)
         * [DPDK parameters](#dpdk-parameters)
      * [Usage](#usage)
         * [Configuration with IPAM:](#configuration-with-ipam)
         * [Configuration with DPDK:](#configuration-with-dpdk)
      * [Contacts](#contacts)

# SR-IOV CNI plugin
This repository is build based on [Intel-sriov-cni Version](https://github.com/Intel-Corp/sriov-cni) which contains the sriov CNI plugin that allows DPDK driver binding as well as the orginal featuers of [sriov-cni](https://github.com/hustcat/sriov-cni). To learn about CNI please visit [containernetworking/cni](https://github.com/containernetworking/cni).

NIC with [SR-IOV](http://blog.scottlowe.org/2009/12/02/what-is-sr-iov/) capabilities works by introducing the idea of physical functions (PFs) and virtual functions (VFs). 

PF is used by host. Each VFs can be treated as a separate physical NIC and assigned to one container, and configured with separate MAC, VLAN and IP, etc.

## changes
compare with Inter's sriov-cni, I made some changes.
1. saving conf-file before the dpdk enabled. So if dpdk failed, this conf-file won't be deleted.
2. I'm assuming that the conf-file(containID-If0name), which it's created in the dpdk-mod process, is used to help user to find which  PCI-address is being used. I found that the containID is the k8s_POD's containID, not the container we acctually used. It's hard for the container to distinguish which conf-file belongs to it. Default, different pods get different networkNameSpaces. So I add a dir which is named after the container's networkNamespace. As all the container in the same pod share the same networkNameSpaces, they can eaily get their conf-file.
Here is the changes. I have tested them on our lab, it works.
1. create the conf-file after the dpdk-mode enabled successfuly;
2. save the conf-file as "CNIDir/networkNameSpace/containerID-If0name" instand of "CNIDir/containerID-If0name"
3. create the conf-file for all sriov-mod;
2. add sriov-PF mode according to the VF code.


## Build

This plugin requires Go 1.5+ to build.

Go 1.5 users will need to set `GO15VENDOREXPERIMENT=1` to get vendored dependencies. This flag is set by default in 1.6.

```
#./build
```

Upon successful build the plugin binary will be available in `bin/sriov`. 

## Enable SR-IOV

Given Intel ixgbe NIC on CentOS, Fedora or RHEL:

	# vi /etc/modprobe.conf
	options ixgbe max_vfs=8,8


## Configuration reference
### Main parameters
* `name` (string, required): the name of the network
* `type` (string, required): "sriov"
* `if0` (string, required): name of the PF
* `if0name` (string, optional): interface name in the Container
* `l2enable` (boolean, optional): if `true` then add VF as L2 mode only, IPAM will not be executed
* `vlan` (int, optional): VLAN ID to assign for the VF
* `ipam` (dictionary, optional): IPAM configuration to be used for this network.
* `dpdk` (dictionary, optional): DPDK configuration
* `PFOnly` (boolean, optional): if `true` then use PF, else use VF, default `false`
*  `CNIDir` (dictionary, optional): the dic to store the conf files, default `var/lib/cni/sriov`

### Using DPDK drivers:
If this plugin is use to bind a VF to dpdk driver then the IPAM configtuations will be ignored.

### DPDK parameters
If given, The DPDK configuration expected to have the following parameters

* `kernel_driver` (string, required): kernel driver name
* `dpdk_driver` (string, required): DPDK capable driver name
* `dpdk_tool` (string, required): path to the dpdk-devbind.py script


## Usage

### Configuration with IPAM using VF:
	# cat > /etc/cni/net.d/10-mynet.conf <<EOF
	{
	    "name": "mynet",
	    "type": "sriov",
	    "if0": "enp1s0f1",
        "pfOnly": false,
	    "ipam": {
	        "type": "host-local",
	        "subnet": "10.55.206.0/26",
	        "routes": [
	            { "dst": "0.0.0.0/0" }
	        ],
	        "gateway": "10.55.206.1"
	    }
	}
	EOF


	eth0      Link encap:Ethernet  HWaddr 66:D8:02:77:AA:AA  
	          inet addr:10.55.206.46  Bcast:0.0.0.0  Mask:255.255.255.192
	          inet6 addr: fe80::64d8:2ff:fe77:aaaa/64 Scope:Link
	          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
	          RX packets:7 errors:0 dropped:0 overruns:0 frame:0
	          TX packets:14 errors:0 dropped:0 overruns:0 carrier:0
	          collisions:0 txqueuelen:1000 
	          RX bytes:530 (530.0 b)  TX bytes:988 (988.0 b)
	
	lo        Link encap:Local Loopback  
	          inet addr:127.0.0.1  Mask:255.0.0.0
	          inet6 addr: ::1/128 Scope:Host
	          UP LOOPBACK RUNNING  MTU:65536  Metric:1
	          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
	          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
	          collisions:0 txqueuelen:0 
	          RX bytes:0 (0.0 b)  TX bytes:0 (0.0 b)


### Configuration with DPDK using VF:


	# cat > /etc/cni/net.d/20-mynet-dpdk.conf <<EOF
	{
	    "name": "mynet",
	    "type": "sriov",
	    "if0": "enp1s0f1",
	    "if0name": "net0",
        "pfOnly": false,
	    "dpdk": {
	        "kernel_driver":"ixgbevf",
	        "dpdk_driver":"igb_uio",
	        "dpdk_tool":"/opt/dpdk/usertools/dpdk-devbind.py"
	    }
	}
	EOF



[More info](https://github.com/containernetworking/cni/pull/259).

## Contacts
For any questions about my sriov-cni version, please reach out on github issue or feel free to contact me @xftony by [e-mail](srl11@foxmail.com)
