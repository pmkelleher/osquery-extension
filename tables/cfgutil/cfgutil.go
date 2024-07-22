package cfgutil

import (
	"encoding/json"
	"os"
	"os/exec"

	"github.com/pkg/errors"
)

type CommandExecutor interface {
	ExecCommand(command string, args ...string) ([]byte, error)
}

type CmdExecutor struct{}

func (r CmdExecutor) ExecCommand(name string, args ...string) ([]byte, error) {
	if _, err := os.Stat(name); os.IsNotExist(err) {
		return nil, errors.Wrap(err, "binary is not installed")
	}

	cmd := exec.Command(name, args...)
	// Some shell commands always log to stderr and will pollute osqueryi output if this is set
	// cmd.Stderr = os.Stderr
	return cmd.Output()
}

type Device struct {
	AcceptsSupervision          bool   `json:"acceptsSupervision"`
	ActivationState             string `json:"activationState"`
	AppDiskUsage                uint64 `json:"appDiskUsage"`
	AudioDiskUsage              uint64 `json:"audioDiskUsage"`
	BackupWillBeEncrypted       bool   `json:"backupWillBeEncrypted"`
	BatteryCurrentCapacity      int    `json:"batteryCurrentCapacity"`
	BatteryIsCharging           bool   `json:"batteryIsCharging"`
	BluetoothAddress            string `json:"bluetoothAddress"`
	BooksDiskUsage              uint64 `json:"booksDiskUsage"`
	BootedState                 string `json:"bootedState"`
	BuildVersion                string `json:"buildVersion"`
	CloudBackupsAreEnabled      bool   `json:"cloudBackupsAreEnabled"`
	Color                       string `json:"color"`
	DeviceClass                 string `json:"deviceClass"`
	DeviceType                  string `json:"deviceType"`
	DocumentsDiskUsage          uint64 `json:"documentsDiskUsage"`
	ECID                        string `json:"ECID"`
	EnclosureColor              string `json:"enclosureColor"`
	EthernetAddress             string `json:"ethernetAddress"`
	FirmwareVersion             string `json:"firmwareVersion"`
	FreeDiskSpace               uint64 `json:"freeDiskSpace"`
	HasTelephonyCapability      bool   `json:"hasTelephonyCapability"`
	HumanReadableProductVersion string `json:"humanReadableProductVersion"`
	ICCID                       string `json:"ICCID"`
	ICCID2                      string `json:"ICCID2"`
	IMEI                        string `json:"IMEI"`
	IMEI2                       string `json:"IMEI2"`
	IsPaired                    bool   `json:"isPaired"`
	IsRestorable                bool   `json:"isRestorable"`
	IsSupervised                bool   `json:"isSupervised"`
	Language                    string `json:"language"`
	Locale                      string `json:"locale"`
	LocationID                  int    `json:"locationID"`
	LogsDiskUsage               uint64 `json:"logsDiskUsage"`
	Name                        string `json:"name"`
	OrganizationAddress         string `json:"organizationAddress"`
	OrganizationDepartment      string `json:"organizationDepartment"`
	OrganizationEmail           string `json:"organizationEmail"`
	OrganizationMagic           string `json:"organizationMagic"`
	OrganizationName            string `json:"organizationName"`
	OrganizationPhone           string `json:"organizationPhone"`
	OtherDiskUsage              uint64 `json:"otherDiskUsage"`
	PairingAllowed              bool   `json:"pairingAllowed"`
	PasscodeProtected           bool   `json:"passcodeProtected"`
	PhoneNumber                 string `json:"phoneNumber"`
	PhoneNumber2                string `json:"phoneNumber2"`
	PhotosDiskUsage             uint64 `json:"photosDiskUsage"`
	PortNumber                  int    `json:"portNumber"`
	SerialNumber                string `json:"serialNumber"`
	StationNumber               int    `json:"stationNumber"`
	SupplementalBuildVersion    string `json:"supplementalBuildVersion"`
	TotalDiskCapacity           uint64 `json:"totalDiskCapacity"`
	TotalSpaceAvailable         uint64 `json:"totalSpaceAvailable"`
	UDID                        string `json:"UDID"`
	VideoDiskUsage              uint64 `json:"videoDiskUsage"`
	WifiAddress                 string `json:"wifiAddress"`
}

type CommandOutput struct {
	Command string            `json:"Command"`
	Output  map[string]Device `json:"Output"`
	Type    string            `json:"Type"`
	Devices []string          `json:"Devices"`
}

func getCommandOutput(cmdExecutor CommandExecutor, isList bool, ECIDS ...string) (CommandOutput, error) {
	var commandOutput CommandOutput

	bytes, err := queryCfgutil(cmdExecutor, isList, ECIDS...)
	if err != nil {
		return commandOutput, errors.Wrap(err, "cfgutil")
	}

	err = json.Unmarshal(bytes, &commandOutput)
	if err != nil {
		return commandOutput, errors.Wrap(err, "json.Unmarshal")
	}

	return commandOutput, nil
}

func queryCfgutil(cmdExecutor CommandExecutor, isList bool, ECIDS ...string) ([]byte, error) {
	cfgutilArgs := []string{"--format", "json"}

	if isList {
		cfgutilArgs = append(cfgutilArgs, "list")
	} else {
		for _, ecid := range ECIDS {
			cfgutilArgs = append(cfgutilArgs, "-e", ecid)
		}
		cfgutilArgs = append(cfgutilArgs, "-f", "get", "all")
	}
	out, err := cmdExecutor.ExecCommand("/usr/local/bin/cfgutil", cfgutilArgs...)
	if err != nil {
		return out, errors.Wrap(err, "cfgutil command failed")
	}
	return out, nil
}

func BoolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
