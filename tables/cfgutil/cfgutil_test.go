package cfgutil

import (
	"errors"
	"fmt"
	"testing"

	"github.com/osquery/osquery-go/plugin/table"
	"github.com/stretchr/testify/assert"
)

func TestExecCommand(t *testing.T) {
	cmdExecutor := CmdExecutor{}
	result, err := cmdExecutor.ExecCommand("/bin/echo", "hello")
	assert.NoError(t, err)
	assert.Equal(t, "hello\n", string(result))
}

type MockCommandExecutor struct{}

func (m MockCommandExecutor) ExecCommand(name string, args ...string) ([]byte, error) {
	// /usr/local/bin/cfgutil --format json list
	if len(args) > 0 && args[len(args)-1] == "list" {
		fmt.Println("Returning mockListJSON")
		return mockListJSON, nil
	}
	// /usr/local/bin/cfgutil --format json ... -f get all
	if len(args) > 0 && args[len(args)-1] == "all" {
		fmt.Println("Returning mockAllJSON")
		return mockAllJSON, nil
	}
	return nil, errors.New("command failed")
}

func TestListColumns(t *testing.T) {
	columns := CfgutilListColumns()
	expectedColumns := []table.ColumnDefinition{
		table.IntegerColumn("location_id"),
		table.TextColumn("udid"),
		table.TextColumn("ecid"),
		table.TextColumn("name"),
		table.TextColumn("device_type"),
	}
	assert.Equal(t, expectedColumns, columns)
}

func TestCfgutilListGenerate(t *testing.T) {
	mockCmdExecutor := MockCommandExecutor{}
	results, err := getCommandOutput(mockCmdExecutor, true)
	marshaledResults := marshalCfgutilList(results)

	expectedResults := []map[string]string{
		{
			"location_id": "37748736",
			"udid":        "60caa2c5dd9b45af8531290a69d5ecb1f62e0d0b",
			"ecid":        "0x908DA3869AF26",
			"name":        "iPhone",
			"device_type": "iPhone8,1",
		},
		{
			"location_id": "1048576",
			"udid":        "00008110-0016594A1492801E",
			"ecid":        "0x16594A1492801E",
			"name":        "iPad",
			"device_type": "iPad14,1",
		},
		{
			"location_id": "36700160",
			"udid":        "36850d5547880075f9c38a44fedb7ed4db385418",
			"ecid":        "0x12109C3804402E",
			"name":        "iPhone",
			"device_type": "iPhone10,5",
		},
	}

	assert.NoError(t, err)
	assert.Equal(t, expectedResults, marshaledResults, "Expected output does not match real output")
}

func TestGetColumns(t *testing.T) {
	columns := CfgutilGetColumns()
	expectedColumns := []table.ColumnDefinition{
		table.IntegerColumn("location_id"),
		table.TextColumn("udid"),
		table.TextColumn("ecid"),
		table.TextColumn("name"),
		table.TextColumn("device_type"),
		table.IntegerColumn("app_disk_usage"),
		table.IntegerColumn("audio_disk_usage"),
		table.IntegerColumn("backup_will_be_encrypted"),
		table.IntegerColumn("battery_current_capacity"),
		table.IntegerColumn("battery_is_charging"),
		table.TextColumn("bluetooth_address"),
		table.IntegerColumn("books_disk_usage"),
		table.TextColumn("booted_state"),
		table.TextColumn("build_version"),
		table.IntegerColumn("cloud_backups_are_enabled"),
		table.TextColumn("color"),
		table.TextColumn("device_class"),
		table.IntegerColumn("documents_disk_usage"),
		table.TextColumn("enclosure_color"),
		table.TextColumn("ethernet_address"),
		table.TextColumn("firmware_version"),
		table.IntegerColumn("free_disk_space"),
		table.IntegerColumn("has_telephony_capability"),
		table.TextColumn("human_readable_product_version"),
		table.TextColumn("iccid"),
		table.TextColumn("iccid2"),
		table.TextColumn("imei"),
		table.TextColumn("imei2"),
		table.IntegerColumn("is_paired"),
		table.IntegerColumn("is_restorable"),
		table.IntegerColumn("is_supervised"),
		table.TextColumn("language"),
		table.TextColumn("locale"),
		table.IntegerColumn("logs_disk_usage"),
		table.TextColumn("organization_address"),
		table.TextColumn("organization_department"),
		table.TextColumn("organization_email"),
		table.TextColumn("organization_magic"),
		table.TextColumn("organization_name"),
		table.TextColumn("organization_phone"),
		table.IntegerColumn("other_disk_usage"),
		table.IntegerColumn("pairing_allowed"),
		table.IntegerColumn("passcode_protected"),
		table.TextColumn("phone_number"),
		table.TextColumn("phone_number2"),
		table.IntegerColumn("photos_disk_usage"),
		table.IntegerColumn("port_number"),
		table.TextColumn("serial_number"),
		table.IntegerColumn("station_number"),
		table.TextColumn("supplemental_build_version"),
		table.IntegerColumn("total_disk_capacity"),
		table.IntegerColumn("total_space_available"),
		table.IntegerColumn("video_disk_usage"),
		table.TextColumn("wifi_address"),
	}
	assert.Equal(t, expectedColumns, columns)
}

func TestCfgutilGetGenerate(t *testing.T) {
	mockCmdExecutor := MockCommandExecutor{}
	results, err := getCommandOutput(mockCmdExecutor, false)
	marshaledResults := marshalCfgutilGet(results)

	expectedResults := []map[string]string{
		{
			"app_disk_usage":                 "0",
			"audio_disk_usage":               "0",
			"backup_will_be_encrypted":       "0",
			"battery_current_capacity":       "100",
			"battery_is_charging":            "0",
			"bluetooth_address":              "08:ff:44:91:9d:3e",
			"books_disk_usage":               "0",
			"booted_state":                   "Booted",
			"build_version":                  "21D50",
			"cloud_backups_are_enabled":      "0",
			"color":                          "1",
			"device_class":                   "iPad",
			"device_type":                    "iPad14,1",
			"documents_disk_usage":           "1232805888",
			"ecid":                           "0x16594A1492801E",
			"enclosure_color":                "6",
			"ethernet_address":               "08:ff:44:8c:a4:41",
			"firmware_version":               "17.3",
			"free_disk_space":                "50790563840",
			"has_telephony_capability":       "0",
			"human_readable_product_version": "17.3",
			"iccid":                          "",
			"iccid2":                         "",
			"imei":                           "",
			"imei2":                          "",
			"is_paired":                      "1",
			"is_restorable":                  "1",
			"is_supervised":                  "0",
			"language":                       "en-US",
			"locale":                         "en_US",
			"location_id":                    "1048576",
			"logs_disk_usage":                "20131840",
			"name":                           "iPad",
			"organization_address":           "",
			"organization_department":        "",
			"organization_email":             "",
			"organization_magic":             "",
			"organization_name":              "",
			"organization_phone":             "",
			"other_disk_usage":               "11224196356",
			"pairing_allowed":                "1",
			"passcode_protected":             "0",
			"phone_number":                   "",
			"phone_number2":                  "",
			"photos_disk_usage":              "5346974",
			"port_number":                    "0",
			"serial_number":                  "VKV40Y96Y6",
			"station_number":                 "0",
			"supplemental_build_version":     "21D50",
			"total_disk_capacity":            "64000000000",
			"total_space_available":          "63983177728",
			"udid":                           "00008110-0016594A1492801E",
			"video_disk_usage":               "0",
			"wifi_address":                   "08:ff:44:8c:45:e5",
		},
		{
			"app_disk_usage":                 "0",
			"audio_disk_usage":               "0",
			"backup_will_be_encrypted":       "0",
			"battery_current_capacity":       "100",
			"battery_is_charging":            "0",
			"bluetooth_address":              "8c:86:1e:ac:2f:6a",
			"books_disk_usage":               "0",
			"booted_state":                   "Booted",
			"build_version":                  "21F90",
			"cloud_backups_are_enabled":      "0",
			"color":                          "1",
			"device_class":                   "iPhone",
			"device_type":                    "iPhone12,3",
			"documents_disk_usage":           "2077069312",
			"ecid":                           "0xA696901F0802E",
			"enclosure_color":                "18",
			"ethernet_address":               "8c:86:1e:b2:e5:80",
			"firmware_version":               "17.5.1",
			"free_disk_space":                "240408899584",
			"has_telephony_capability":       "1",
			"human_readable_product_version": "17.5.1",
			"iccid":                          "89014103273306396536",
			"iccid2":                         "",
			"imei":                           "353237100347021",
			"imei2":                          "353237100503375",
			"is_paired":                      "1",
			"is_restorable":                  "1",
			"is_supervised":                  "1",
			"language":                       "en-US",
			"locale":                         "en_US",
			"location_id":                    "17825792",
			"logs_disk_usage":                "20738048",
			"name":                           "iPhone",
			"organization_address":           "5555 Acme Drive\nAcme Island, AK 55555",
			"organization_department":        "",
			"organization_email":             "mdm@acme.io",
			"organization_magic":             "68885D0C-DE37-48C5-98ED-DC52ACA6898E",
			"organization_name":              "acme",
			"organization_phone":             "555-555-5555",
			"other_disk_usage":               "18446744029357912988",
			"pairing_allowed":                "1",
			"passcode_protected":             "1",
			"phone_number":                   "+1 (555) 555-5555",
			"phone_number2":                  "",
			"photos_disk_usage":              "7299326",
			"port_number":                    "0",
			"serial_number":                  "C39ZC2ZGN6XW",
			"station_number":                 "0",
			"supplemental_build_version":     "21F90",
			"total_disk_capacity":            "256000000000",
			"total_space_available":          "255881465856",
			"udid":                           "00008030-000A696901F0802E",
			"video_disk_usage":               "0",
			"wifi_address":                   "8c:86:1e:ba:aa:6c",
		},
	}

	assert.NoError(t, err)
	assert.Equal(t, expectedResults, marshaledResults, "Expected output does not match real output")
}
