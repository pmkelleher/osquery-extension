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
		return nil, errors.Wrap(err, "cfgutil binary is not installed")
	}

	cmd := exec.Command(name, args...)
	// Some shell commands always log to stderr and will pollute osqueryi output if this is set
	// cmd.Stderr = os.Stderr
	return cmd.Output()
}

type Device struct {
	LocationID int    `json:"locationID"`
	UDID       string `json:"UDID"`
	ECID       string `json:"ECID"`
	Name       string `json:"name"`
	DeviceType string `json:"deviceType"`
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
		cfgutilArgs = append(cfgutilArgs, "get", "all")
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
