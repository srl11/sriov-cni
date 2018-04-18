package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/containernetworking/cni/pkg/ipam"
	"github.com/containernetworking/cni/pkg/ns"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/vishvananda/netlink"
)

const defaultCNIDir = "/var/lib/cni/sriov"
const maxSharedVf = 2

var stdoutOld = os.Stdout

type dpdkConf struct {
	PCIaddr    string `json:"pci_addr"`
	Ifname     string `json:"ifname"`
	KDriver    string `json:"kernel_driver"`
	DPDKDriver string `json:"dpdk_driver"`
	DPDKtool   string `json:"dpdk_tool"`
	VFID       int    `json: "vfid"`
}

type NetConf struct {
	types.NetConf
	DPDKMode bool
	Sharedvf bool
	DPDKConf dpdkConf `json:"dpdk,omitempty"`
	CNIDir   string   `json:"cniDir"`
	IF0      string   `json:"if0"`
	IF0NAME  string   `json:"if0name"`
	L2Mode   bool     `json:"l2enable"`
	Vlan     int      `json:"vlan"`
	PFOnly   bool     `json:"pfOnly"`
	PCIaddr  string   `json:"pci_addr"`
}

func init() {
	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
}

func checkIf0name(ifname string) bool {
	op := []string{"eth0", "eth1", "lo", ""}
	for _, if0name := range op {
		if strings.Compare(if0name, ifname) == 0 {
			return false
		}
	}

	return true
}

func loadConf(bytes []byte) (*NetConf, error) {
	n := &NetConf{}
	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, fmt.Errorf("failed to load netconf: %v", err)
	}

	if n.IF0NAME != "" {
		err := checkIf0name(n.IF0NAME)
		if err != true {
			return nil, fmt.Errorf(`"if0name" field should not be  equal to (eth0 | eth1 | lo | ""). It specifies the virtualized interface name in the pod`)
		}
	}

	if n.IF0 == "" {
		return nil, fmt.Errorf(`"if0" field is required. It specifies the host interface name to virtualize`)
	}

	if n.CNIDir == "" {
		n.CNIDir = defaultCNIDir
	}

	if (dpdkConf{}) != n.DPDKConf {
		n.DPDKMode = true
	}

	return n, nil
}

func PathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func PathEmpty(path string) (bool, error) {

	exist, err := PathExists(path)

	if exist == false {
		return false, err
	}

	dir, _ := ioutil.ReadDir(path)
	if len(dir) == 0 {
		return true, nil
	}

	return false, nil
}

func saveScratchNetConf(containerID, dataDir string, netconf []byte, nsfd string) error {
	netNs, err := os.Readlink(nsfd)
	if err != nil {
		return fmt.Errorf("can't read the netNs link of nsfd:(%q), %v", nsfd, err)
	}
	netNsNum := netNs[1+strings.Index(netNs, "[") : strings.Index(netNs, "]")]
	newDataDir := filepath.Join(dataDir, netNsNum)

	if err := os.MkdirAll(newDataDir, 0700); err != nil {
		return fmt.Errorf("failed to create the sriov data directory(%q): %v", dataDir, err)
	}

	path := filepath.Join(newDataDir, containerID)
	err = ioutil.WriteFile(path, netconf, 0600)
	if err != nil {
		return fmt.Errorf("failed to write container data in the path(%q): %v", path, err)
	}

	return err
}

func consumeScratchNetConf(fileName, dataDir string, nsfd string) ([]byte, error) {
	netNs, err := os.Readlink(nsfd)
	if err != nil {
		return nil, fmt.Errorf("can't read the netNs link of nsfd:(%q), %v", nsfd, err)
	}
	netNsNum := netNs[1+strings.Index(netNs, "[") : strings.Index(netNs, "]")]
	newDataDir := filepath.Join(dataDir, netNsNum)

	filePath := filepath.Join(newDataDir, fileName)

	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read container data in the path(%q): %v", fileName, err)
	}

	os.Remove(filePath)

	empty, err := PathEmpty(newDataDir)
	if empty == true {
		os.Remove(newDataDir)
	}
	return data, err
}

func saveConf(cid, dataDir string, conf *NetConf, nsfd string) error {
	confBytes, err := json.Marshal(conf)
	if err != nil {
		return fmt.Errorf("error serializing delegate netconf: %v", err)
	}

	s := []string{cid, conf.IF0NAME}
	cRef := strings.Join(s, "-")

	// save the rendered netconf for cmdDel
	if err = saveScratchNetConf(cRef, dataDir, confBytes, nsfd); err != nil {
		return err
	}

	return nil
}

func (dc *NetConf) getConf(cid, dataDir string, conf *NetConf, nsfd string) error { //xftony
	s := []string{cid, conf.IF0NAME}
	cRef := strings.Join(s, "-")

	confBytes, err := consumeScratchNetConf(cRef, dataDir, nsfd) //xftony
	if err != nil {
		return err
	}

	if err = json.Unmarshal(confBytes, dc); err != nil {
		return fmt.Errorf("failed to parse netconf: %v", err)
	}

	return nil
}

func enabledpdkmode(conf *dpdkConf, ifname string, dpdkmode bool) error {
	stdout := &bytes.Buffer{}
	var driver string
	var device string

	if dpdkmode != false {
		driver = conf.DPDKDriver
		device = ifname
	} else {
		driver = conf.KDriver
		device = conf.PCIaddr
	}

	cmd := exec.Command(conf.DPDKtool, "-b", driver, device)
	cmd.Stdout = stdout
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("DPDK binding failed with err msg %q:", stdout.String(), driver, device)
	}

	stdout.Reset()
	return nil
}

func getpciaddress(ifName string, vf int) (string, error) {
	var pciaddr string
	vfDir := fmt.Sprintf("/sys/class/net/%s/device/virtfn%d", ifName, vf)
	dirInfo, err := os.Lstat(vfDir)
	if err != nil {
		return pciaddr, fmt.Errorf("can't get the symbolic link of virtfn%d dir of the device %q: %v", vf, ifName, err)
	}

	if (dirInfo.Mode() & os.ModeSymlink) == 0 {
		return pciaddr, fmt.Errorf("No symbolic link for the virtfn%d dir of the device %q", vf, ifName)
	}

	pciinfo, err := os.Readlink(vfDir)
	if err != nil {
		return pciaddr, fmt.Errorf("can't read the symbolic link of virtfn%d dir of the device %q: %v", vf, ifName, err)
	}

	pciaddr = pciinfo[len("../"):]
	return pciaddr, nil
}

func getPFPciAddress(ifName string) (string, error) {
	var pciaddr string
	pfDir := fmt.Sprintf("/sys/class/net/%s/device", ifName)
	dirInfo, err := os.Lstat(pfDir)
	if err != nil {
		return pciaddr, fmt.Errorf("can't get the symbolic link of PF dir of the device %q: %v", ifName, err)
	}

	if (dirInfo.Mode() & os.ModeSymlink) == 0 {
		return pciaddr, fmt.Errorf("No symbolic link for the PF dir of the device %q", ifName)
	}

	pciinfo, err := os.Readlink(pfDir)
	if err != nil {
		return pciaddr, fmt.Errorf("can't read the symbolic link of PF dir of the device %q: %v", ifName, err)
	}

	pciaddr = pciinfo[len("../../../"):]
	return pciaddr, nil
}

func getSharedPF(ifName string) (string, error) {
	pfName := ""
	pfDir := fmt.Sprintf("/sys/class/net/%s", ifName)
	dirInfo, err := os.Lstat(pfDir)
	if err != nil {
		return pfName, fmt.Errorf("can't get the symbolic link of the device %q: %v", ifName, err)
	}

	if (dirInfo.Mode() & os.ModeSymlink) == 0 {
		return pfName, fmt.Errorf("No symbolic link for dir of the device %q", ifName)
	}

	fullpath, err := filepath.EvalSymlinks(pfDir)
	parentDir := fullpath[:len(fullpath)-len(ifName)]
	dirList, err := ioutil.ReadDir(parentDir)

	for _, file := range dirList {
		if file.Name() != ifName {
			pfName = file.Name()
			return pfName, nil
		}
	}

	return pfName, fmt.Errorf("Shared PF not found")
}

func getsriovNumfs(ifName string) (int, error) {
	var vfTotal int

	sriovFile := fmt.Sprintf("/sys/class/net/%s/device/sriov_numvfs", ifName)
	if _, err := os.Lstat(sriovFile); err != nil {
		return vfTotal, fmt.Errorf("failed to open the sriov_numfs of device %q: %v", ifName, err)
	}

	data, err := ioutil.ReadFile(sriovFile)
	if err != nil {
		return vfTotal, fmt.Errorf("failed to read the sriov_numfs of device %q: %v", ifName, err)
	}

	if len(data) == 0 {
		return vfTotal, fmt.Errorf("no data in the file %q", sriovFile)
	}

	sriovNumfs := strings.TrimSpace(string(data))
	vfTotal, err = strconv.Atoi(sriovNumfs)
	if err != nil {
		return vfTotal, fmt.Errorf("failed to convert sriov_numfs(byte value) to int of device %q: %v", ifName, err)
	}

	return vfTotal, nil
}

func setSharedVfVlan(ifName string, vfIdx int, vlan int) error {
	var err error
	var sharedifName string

	vfDir := fmt.Sprintf("/sys/class/net/%s/device/net", ifName)
	if _, err := os.Lstat(vfDir); err != nil {
		return fmt.Errorf("failed to open the net dir of the device %q: %v", ifName, err)
	}

	infos, err := ioutil.ReadDir(vfDir)
	if err != nil {
		return fmt.Errorf("failed to read the net dir of the device %q: %v", ifName, err)
	}

	if len(infos) != maxSharedVf {
		return fmt.Errorf("Given PF - %q is not having shared VF", ifName)
	}

	for _, dir := range infos {
		if strings.Compare(ifName, dir.Name()) != 0 {
			sharedifName = dir.Name()
		}
	}

	if sharedifName == "" {
		return fmt.Errorf("Shared ifname can't be empty")
	}

	iflink, err := netlink.LinkByName(sharedifName)
	if err != nil {
		return fmt.Errorf("failed to lookup the shared ifname %q: %v", sharedifName, err)
	}

	if err := netlink.LinkSetVfVlan(iflink, vfIdx, vlan); err != nil {
	}

	return nil
}

func setupVF(conf *NetConf, ifName string, podifName string, cid string, netns ns.NetNS, nsfd string) error {

	var vfIdx int
	var infos []os.FileInfo
	var pciAddr string
	m, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("failed to lookup master %q: %v", conf.IF0, err)
	}

	// get the ifname sriov vf num
	vfTotal, err := getsriovNumfs(ifName)
	if err != nil {
		return err
	}

	if vfTotal <= 0 {
		return fmt.Errorf("no virtual function in the device %q: %v", ifName)
	}

	for vf := 0; vf <= (vfTotal - 1); vf++ {
		vfDir := fmt.Sprintf("/sys/class/net/%s/device/virtfn%d/net", ifName, vf)
		if _, err := os.Lstat(vfDir); err != nil {
			if vf == (vfTotal - 1) {
				return fmt.Errorf("failed to open the virtfn%d dir of the device %q: %v", vf, ifName, err)
			}
			continue
		}

		infos, err = ioutil.ReadDir(vfDir)
		if err != nil {
			return fmt.Errorf("failed to read the virtfn%d dir of the device %q: %v", vf, ifName, err)
		}

		if (len(infos) == 0) && (vf == (vfTotal - 1)) {
			return fmt.Errorf("no Virtual function exist in directory %s, last vf is virtfn%d", vfDir, vf)
		}

		if (len(infos) == 0) && (vf != (vfTotal - 1)) {
			continue
		}

		if len(infos) == maxSharedVf {
			conf.Sharedvf = true
		}

		if len(infos) <= maxSharedVf {
			vfIdx = vf
			pciAddr, err = getpciaddress(ifName, vfIdx)
                        conf.PCIaddr = pciAddr
			if err != nil {
				return fmt.Errorf("err in getting pci address - %q", err)
			}
			break
		} else {
			return fmt.Errorf("mutiple network devices in directory %s", vfDir)
		}
	}

	// VF NIC name
	if len(infos) != 1 && len(infos) != maxSharedVf {
		return fmt.Errorf("no virutal network resources avaiable for the %q", conf.IF0)
	}

	if conf.Sharedvf != false && conf.L2Mode != true {
		return fmt.Errorf("l2enable mode must be true to use shared net interface %q", conf.IF0)
	}

	if conf.DPDKMode != false {
		conf.DPDKConf.PCIaddr = pciAddr
		conf.DPDKConf.Ifname = podifName
		conf.DPDKConf.VFID = vfIdx

		if err = enabledpdkmode(&conf.DPDKConf, infos[0].Name(), true); err != nil {
			return err
		}
		return nil
	}

	for i := 1; i <= len(infos); i++ {
		vfDev, err := netlink.LinkByName(infos[i-1].Name())
		if err != nil {
			return fmt.Errorf("failed to lookup vf device %q: %v", infos[i-1].Name(), err)
		}

		if conf.Vlan != 0 {
			if err = netlink.LinkSetVfVlan(m, vfIdx, conf.Vlan); err != nil {
				return fmt.Errorf("failed to set vf %d vlan: %v", vfIdx, err)
			}
		}

		if conf.Vlan != 0 && conf.Sharedvf != false && conf.L2Mode != false {
			if err = setSharedVfVlan(ifName, vfIdx, conf.Vlan); err != nil {
				return fmt.Errorf("failed to set shared vf %d vlan: %v", vfIdx, err)
			}
		}
		if err = netlink.LinkSetUp(vfDev); err != nil {
			return fmt.Errorf("failed to setup vf %d device: %v", vfIdx, err)
		}

		// move VF device to ns
		if err = netlink.LinkSetNsFd(vfDev, int(netns.Fd())); err != nil {
			return fmt.Errorf("failed to move vf %d to netns: %v", vfIdx, err)
		}
	}

	return netns.Do(func(_ ns.NetNS) error {

		ifName := podifName
		for i := 1; i <= len(infos); i++ {
			if len(infos) == maxSharedVf && i == len(infos) {
				ifName = podifName + fmt.Sprintf("d%d", i-1)
			}

			err := renameLink(infos[i-1].Name(), ifName)
			if err != nil {
				return fmt.Errorf("failed to rename %d vf of the device %q to %q: %v", vfIdx, infos[i-1].Name(), ifName, err)
			}

			// for L2 mode enable the pod net interface
			if conf.L2Mode != false {
				err = setUpLink(ifName)
				if err != nil {
					return fmt.Errorf("failed to set up the pod interface name %q: %v", ifName, err)
				}
			}
		}
		return nil
	})
}

func setupPF(conf *NetConf, ifName string, podifName string, cid string, netns ns.NetNS, nsfd string) error {
	var pciAddr string

	m, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("failed to lookup master %q: %v", ifName, err)
	}

	pfDir := fmt.Sprintf("/sys/class/net/")
	if _, err := os.Lstat(pfDir); err != nil {
		return fmt.Errorf("failed to open the PF dir of the device %q: %v", ifName, err)
	}

	if err != nil {
		return fmt.Errorf("failed to read the PF dir of the device %q: %v", pfDir, err)
	}

	pciAddr, err = getPFPciAddress(ifName)
        conf.PCIaddr = pciAddr
	if err != nil {
		return fmt.Errorf("err in getting pci address - %q", err)
	}

	if conf.DPDKMode != false {
		conf.DPDKConf.PCIaddr = pciAddr
		conf.DPDKConf.Ifname = podifName
		//conf.DPDKConf.VFID = vfIdx
		return enabledpdkmode(&conf.DPDKConf, ifName, true)
	}

	if conf.Vlan != 0 {
		return fmt.Errorf("modifying vlan of PF is not supported")
	}
	if err = netlink.LinkSetUp(m); err != nil {
		return fmt.Errorf("failed to setup PF")
	}

	// move PF device to ns
	if err = netlink.LinkSetNsFd(m, int(netns.Fd())); err != nil {
		return fmt.Errorf("failed to move PF to netns: %v", err)
	}

	return netns.Do(func(_ ns.NetNS) error {
		err := renameLink(ifName, podifName)
		if err != nil {
			return fmt.Errorf("failed to rename PF to %q: %v", ifName, err)
		}
		return nil
	})
}

func releaseVF(conf *NetConf, podifName string, cid string, netns ns.NetNS, nsfd string) error {
	// check for the DPDK mode and release the allocated DPDK resources
	if conf.DPDKMode != false {
		df := &NetConf{}
		// get the DPDK net conf in cniDir
		if err := df.getConf(cid, conf.CNIDir, conf, nsfd); err != nil {
			return err
		}

		// bind the sriov vf to the kernel driver
		if err := enabledpdkmode(&df.DPDKConf, df.IF0NAME, false); err != nil {
			return fmt.Errorf("DPDK: failed to bind %s to kernel space: %s", df.IF0NAME, err)

		}

		// reset vlan for DPDK code here
		pfLink, err := netlink.LinkByName(conf.IF0)
		if err != nil {
			return fmt.Errorf("DPDK: master device %s not found: %v", conf.IF0, err)
		}

		if err = netlink.LinkSetVfVlan(pfLink, df.DPDKConf.VFID, 0); err != nil {
			return fmt.Errorf("DPDK: failed to reset vlan tag for vf %d: %v", df.DPDKConf.VFID, err)
		}

		return nil
	}

	initns, err := ns.GetCurrentNS()
	if err != nil {
		return fmt.Errorf("failed to get init netns: %v", err)
	}

	if err = netns.Set(); err != nil {
		return fmt.Errorf("failed to enter netns %q: %v", netns, err)
	}

	if conf.L2Mode != false {
		//check for the shared vf net interface
		ifName := podifName + "d1"
		_, err := netlink.LinkByName(ifName)
		if err == nil {
			conf.Sharedvf = true
		}

	}

	if err != nil {
		fmt.Errorf("Enable to get shared PF device: %v", err)
	}

	for i := 1; i <= maxSharedVf; i++ {
		ifName := podifName
		pfName := conf.IF0
		if i == maxSharedVf {
			ifName = podifName + fmt.Sprintf("d%d", i-1)
			pfName, err = getSharedPF(conf.IF0)
			if err != nil {
				return fmt.Errorf("Failed to look up shared PF device: %v:", err)
			}
		}

		// get VF device
		vfDev, err := netlink.LinkByName(ifName)
		if err != nil {
			return fmt.Errorf("failed to lookup vf device %q: %v", ifName, err)
		}

		// device name in init netns
		index := vfDev.Attrs().Index
		devName := fmt.Sprintf("dev%d", index)

		// shutdown VF device
		if err = netlink.LinkSetDown(vfDev); err != nil {
			return fmt.Errorf("failed to down vf device %q: %v", ifName, err)
		}

		// rename VF device
		err = renameLink(ifName, devName)
		if err != nil {
			return fmt.Errorf("failed to rename vf device %q to %q: %v", ifName, devName, err)
		}

		// move VF device to init netns
		if err = netlink.LinkSetNsFd(vfDev, int(initns.Fd())); err != nil {
			return fmt.Errorf("failed to move vf device to init netns: %v", ifName, err)
		}

		// reset vlan
		if conf.Vlan != 0 {
			err = initns.Do(func(_ ns.NetNS) error {
				return resetVfVlan(pfName, devName)
			})
			if err != nil {
				return fmt.Errorf("failed to reset vlan: %v", err)
			}
		}

		//break the loop, if the namespace has no shared vf net interface
		if conf.Sharedvf != true {
			break
		}
	}

	return nil
}

func releasePF(conf *NetConf, podifName string, cid string, netns ns.NetNS, nsfd string) error {
	// check for the DPDK mode and release the allocated DPDK resources
	if conf.DPDKMode != false {
		df := &NetConf{}
		// get the DPDK net conf in cniDir
		if err := df.getConf(cid, conf.CNIDir, conf, nsfd); err != nil {
			return err
		}

		// bind the sriov vf to the kernel driver
		if err := enabledpdkmode(&df.DPDKConf, df.IF0NAME, false); err != nil {
			return fmt.Errorf("DPDK: failed to bind %s to kernel space: %s", df.IF0NAME, err)
		}

		// reset vlan for DPDK code here
		pfLink, err := netlink.LinkByName(conf.IF0)
		if err != nil {
			return fmt.Errorf("DPDK: master device %s not found: %v", conf.IF0, err)
		}

		if err = netlink.LinkSetVfVlan(pfLink, df.DPDKConf.VFID, 0); err != nil {
			return fmt.Errorf("DPDK: failed to reset vlan tag for vf %d: %v", df.DPDKConf.VFID, err)
		}

		setupIF0(conf.IF0)
		return nil
	}

	initns, err := ns.GetCurrentNS()
	if err != nil {
		return fmt.Errorf("failed to get init netns: %v", err)
	}

	// for IPAM in cmdDel
	return netns.Do(func(_ ns.NetNS) error {

		// get PF device
		master, err := netlink.LinkByName(podifName)
		ifName := conf.IF0
		if err != nil {
			return fmt.Errorf("failed to lookup device %s: %v", ifName, err)
		}

		// shutdown PF device
		if err = netlink.LinkSetDown(master); err != nil {
			return fmt.Errorf("failed to down device: %v", err)
		}

		// rename PF device
		err = renameLink(podifName, ifName)
		if err != nil {
			return fmt.Errorf("failed to rename device %s to %s: %v", podifName, ifName, err)
		}

		// move PF device to init netns
		if err = netlink.LinkSetNsFd(master, int(initns.Fd())); err != nil {
			return fmt.Errorf("failed to move device %s to init netns: %v", ifName, err)
		}
		// setup PF device
		//setupIF0(ifName)

		return nil
	})
}

func setupIF0(if0 string) error {
	cmdStr := fmt.Sprintf("/sbin/ifconfig %s up", if0)
	cmd := exec.Command("/bin/sh", "-c", cmdStr)
	cmdErr := cmd.Run()
	return cmdErr
}

func resetVfVlan(pfName, vfName string) error {

	// get the ifname sriov vf num
	vfTotal, err := getsriovNumfs(pfName)
	if err != nil {
		return err
	}

	if vfTotal <= 0 {
		return fmt.Errorf("no virtual function in the device %q: %v", pfName)
	}

	// Get VF id
	var vf int
	idFound := false
	for vf = 0; vf < vfTotal; vf++ {
		vfDir := fmt.Sprintf("/sys/class/net/%s/device/virtfn%d/net/%s", pfName, vf, vfName)
		if _, err := os.Stat(vfDir); !os.IsNotExist(err) {
			idFound = true
			break
		}
	}

	if !idFound {
		return fmt.Errorf("failed to get VF id for %s", vfName)
	}

	pfLink, err := netlink.LinkByName(pfName)
	if err != nil {
		return fmt.Errorf("Master device %s not found\n", pfName)
	}

	if err = netlink.LinkSetVfVlan(pfLink, vf, 0); err != nil {
		return fmt.Errorf("failed to reset vlan tag for vf %d: %v", vf, err)
	}
	return nil
}

func cmdAdd(args *skel.CmdArgs) error {
	n, err := loadConf(args.StdinData)
	if err != nil {
		return fmt.Errorf("failed to load netconf: %v", err)
	}

	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", netns, err)
	}

	defer netns.Close()

	if n.IF0NAME != "" {
		args.IfName = n.IF0NAME
	}

        setupIF0(n.IF0) // setup IF0 no matter if up or down
	if n.PFOnly != true {
		if err = setupVF(n, n.IF0, args.IfName, args.ContainerID, netns, args.Netns); err != nil {
			return fmt.Errorf("failed to set up pod VF interface %q from the device %q: %v", args.IfName, n.IF0, err)
		}
	} else {
		if err = setupPF(n, n.IF0, args.IfName, args.ContainerID, netns, args.Netns); err != nil {
			return fmt.Errorf("failed to set up pod PF interface %q from the device %q: %v", args.IfName, n.IF0, err)
		}
	}

	// skip the IPAM allocation for the DPDK and L2 mode
	var result *types.Result
	if n.DPDKMode != false || n.L2Mode != false {
		if err = saveConf(args.ContainerID, n.CNIDir, n, args.Netns); err != nil {
			return err
		}
		os.Stdout = stdoutOld
		return result.Print()
	}

	// run the IPAM plugin and get back the config to apply
	result, err = ipam.ExecAdd(n.IPAM.Type, args.StdinData)
	if err != nil {
		return fmt.Errorf("failed to set up IPAM plugin type %q from the device %q: %v", n.IPAM.Type, n.IF0, err)
	}
	if result.IP4 == nil {
		return errors.New("IPAM plugin returned missing IPv4 config")
	}
	err = netns.Do(func(_ ns.NetNS) error {
		if err = saveConf(args.ContainerID, n.CNIDir, n, args.Netns); err != nil {
			return err
		}
		return ipam.ConfigureIface(args.IfName, result)
	})
	if err != nil {
		return err
	}

	result.DNS = n.DNS
	if err = saveConf(args.ContainerID, n.CNIDir, n, args.Netns); err != nil {
	      return err
        }
	os.Stdout = stdoutOld
	return result.Print()
}

func cmdDel(args *skel.CmdArgs) error {
	n, err := loadConf(args.StdinData)
	if err != nil {
		return err
	}

	// skip the IPAM release for the DPDK and L2 mode
	if n.IPAM.Type != "" {
		err = ipam.ExecDel(n.IPAM.Type, args.StdinData)
		if err != nil {
			return err
		}
	}

	if args.Netns == "" {
		return nil
	}

	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", netns, err)
	}
	defer netns.Close()

	if n.IF0NAME != "" {
		args.IfName = n.IF0NAME
	}
	if n.PFOnly != true {
		if err = releaseVF(n, args.IfName, args.ContainerID, netns, args.Netns); err != nil {
			return err
		}
	} else {
		if err = releasePF(n, args.IfName, args.ContainerID, netns, args.Netns); err != nil {
			return err
		}
	}

	s := []string{args.ContainerID, n.IF0NAME}
	cRef := strings.Join(s, "-")
	consumeScratchNetConf(cRef, n.CNIDir, args.Netns)
	return nil
}

func renameLink(curName, newName string) error {
	link, err := netlink.LinkByName(curName)
	if err != nil {
		return fmt.Errorf("failed to lookup device %q: %v", curName, err)
	}

	return netlink.LinkSetName(link, newName)
}

func setUpLink(ifName string) error {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("failed to set up device %q: %v", ifName, err)
	}

	return netlink.LinkSetUp(link)
}

func main() {
	logDir := "/root/xftony/log/"
	exist, err := PathExists(logDir)
	if exist == false {
		if err = os.MkdirAll(logDir, 0700); err != nil {
			fmt.Errorf("failed to create the logPath directory(%q): %v", logDir, err)
			return
		}
	}
	f, _ := os.OpenFile("/root/xftony/log/sriov.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0755)
	os.Stdout = f
	skel.PluginMain(cmdAdd, cmdDel)
}

