package cfgutil

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

// Device represents the details of a device
type Device struct {
	LocationID int    `json:"locationID"`
	UDID       string `json:"UDID"`
	ECID       string `json:"ECID"`
	Name       string `json:"name"`
	DeviceType string `json:"deviceType"`
}

// CommandOutput represents the top-level structure of the JSON data
type CommandOutput struct {
	Command string            `json:"Command"`
	Output  map[string]Device `json:"Output"`
	Type    string            `json:"Type"`
	Devices []string          `json:"Devices"`
}

func getCommandOutput(cmdExecutor CommandExecutor) (CommandOutput, error) {
	var commandOutput CommandOutput

	bytes, err := runCfgutil(cmdExecutor)
	if err != nil {
		return commandOutput, errors.Wrap(err, "cfgutil")
	}

	err = json.Unmarshal(bytes, &commandOutput)
	if err != nil {
		return commandOutput, errors.Wrap(err, "json.Unmarshal")
	}

	return commandOutput, nil
}

func runCfgutil(cmdExecutor CommandExecutor) ([]byte, error) {
	out, err := cmdExecutor.ExecCommand("/usr/local/bin/cfgutil", "--format", "json", "list")
	if err != nil {
		return out, errors.Wrap(err, "cfgutil --format json list")
	}
	return out, nil
}

func BoolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
