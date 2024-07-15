package tetherator

import (
	"encoding/json"
	"os/exec"

	"github.com/pkg/errors"
)

type CommandExecutor interface {
	ExecCommand(command string, args ...string) ([]byte, error)
}

type CmdExecutor struct{}

func (r CmdExecutor) ExecCommand(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	// Some shell commands always log to stderr and will pollute osqueryi output if this is set
	// cmd.Stderr = os.Stderr
	return cmd.Output()
}

type Status struct {
	Name   string `json:"name"`
	Result Result `json:"result"`
}

type Result struct {
	Active           bool             `json:"Active"`
	DeviceRoster     []Device         `json:"Device Roster"`
	PrimaryInterface PrimaryInterface `json:"Primary Interface"`
	Standalone       bool             `json:"Standalone"`
}

type Device struct {
	Bridged         bool   `json:"Bridged"`
	CheckInAttempts int    `json:"Check In Attempts"`
	CheckInPending  bool   `json:"Check In Pending"`
	CheckedIn       bool   `json:"Checked In"`
	LocationID      int    `json:"Location ID"`
	Name            string `json:"Name"`
	Paired          bool   `json:"Paired"`
	SerialNumber    string `json:"Serial Number"`
}

type PrimaryInterface struct {
	BSDName      string `json:"BSD Name"`
	IPAddress    string `json:"IP Address"`
	Mbps         int    `json:"Mbps"`
	UserReadable string `json:"User Readable"`
	Wired        bool   `json:"Wired"`
}

func getTetheratorStatus(cmdExecutor CommandExecutor) (Status, error) {
	var status Status

	bytes, err := runAssetCacheTetheratorStatus(cmdExecutor)
	if err != nil {
		return status, errors.Wrap(err, "runAssetCacheTetheratorStatus")
	}

	err = json.Unmarshal(bytes, &status)
	if err != nil {
		return status, errors.Wrap(err, "json.Unmarshal")
	}

	return status, nil
}

func runAssetCacheTetheratorStatus(cmdExecutor CommandExecutor) ([]byte, error) {
	out, err := cmdExecutor.ExecCommand("/usr/bin/assetCacheTetheratorUtil", "-j", "status")
	if err != nil {
		return out, errors.Wrap(err, "assetCacheTetheratorUtil -j status")
	}
	return out, nil
}

func BoolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
