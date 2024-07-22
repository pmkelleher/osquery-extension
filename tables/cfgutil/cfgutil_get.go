package cfgutil

import (
	"context"
	"fmt"

	"github.com/osquery/osquery-go/plugin/table"
)

func CfgutilGetColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
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
}

func marshalCfgutilGet(commandOutput CommandOutput) []map[string]string {
	var results []map[string]string

	for key, device := range commandOutput.Output {
		// An Errors dict is very inconveniently nested in Output alongside devices
		if key == "Errors" {
			continue
		}
		results = append(results, map[string]string{
			"location_id":                    fmt.Sprintf("%d", device.LocationID),
			"udid":                           device.UDID,
			"ecid":                           device.ECID,
			"name":                           device.Name,
			"device_type":                    device.DeviceType,
			"app_disk_usage":                 fmt.Sprintf("%d", device.AppDiskUsage),
			"audio_disk_usage":               fmt.Sprintf("%d", device.AudioDiskUsage),
			"backup_will_be_encrypted":       fmt.Sprintf("%d", BoolToInt(device.BackupWillBeEncrypted)),
			"battery_current_capacity":       fmt.Sprintf("%d", device.BatteryCurrentCapacity),
			"battery_is_charging":            fmt.Sprintf("%d", BoolToInt(device.BatteryIsCharging)),
			"bluetooth_address":              device.BluetoothAddress,
			"books_disk_usage":               fmt.Sprintf("%d", device.BooksDiskUsage),
			"booted_state":                   device.BootedState,
			"build_version":                  device.BuildVersion,
			"cloud_backups_are_enabled":      fmt.Sprintf("%d", BoolToInt(device.CloudBackupsAreEnabled)),
			"color":                          device.Color,
			"device_class":                   device.DeviceClass,
			"documents_disk_usage":           fmt.Sprintf("%d", device.DocumentsDiskUsage),
			"enclosure_color":                device.EnclosureColor,
			"ethernet_address":               device.EthernetAddress,
			"firmware_version":               device.FirmwareVersion,
			"free_disk_space":                fmt.Sprintf("%d", device.FreeDiskSpace),
			"has_telephony_capability":       fmt.Sprintf("%d", BoolToInt(device.HasTelephonyCapability)),
			"human_readable_product_version": device.HumanReadableProductVersion,
			"iccid":                          device.ICCID,
			"iccid2":                         device.ICCID2,
			"imei":                           device.IMEI,
			"imei2":                          device.IMEI2,
			"is_paired":                      fmt.Sprintf("%d", BoolToInt(device.IsPaired)),
			"is_restorable":                  fmt.Sprintf("%d", BoolToInt(device.IsRestorable)),
			"is_supervised":                  fmt.Sprintf("%d", BoolToInt(device.IsSupervised)),
			"language":                       device.Language,
			"locale":                         device.Locale,
			"logs_disk_usage":                fmt.Sprintf("%d", device.LogsDiskUsage),
			"organization_address":           device.OrganizationAddress,
			"organization_department":        device.OrganizationDepartment,
			"organization_email":             device.OrganizationEmail,
			"organization_magic":             device.OrganizationMagic,
			"organization_name":              device.OrganizationName,
			"organization_phone":             device.OrganizationPhone,
			"other_disk_usage":               fmt.Sprintf("%d", device.OtherDiskUsage),
			"pairing_allowed":                fmt.Sprintf("%d", BoolToInt(device.PairingAllowed)),
			"passcode_protected":             fmt.Sprintf("%d", BoolToInt(device.PasscodeProtected)),
			"phone_number":                   device.PhoneNumber,
			"phone_number2":                  device.PhoneNumber2,
			"photos_disk_usage":              fmt.Sprintf("%d", device.PhotosDiskUsage),
			"port_number":                    fmt.Sprintf("%d", device.PortNumber),
			"serial_number":                  device.SerialNumber,
			"station_number":                 fmt.Sprintf("%d", device.StationNumber),
			"supplemental_build_version":     device.SupplementalBuildVersion,
			"total_disk_capacity":            fmt.Sprintf("%d", device.TotalDiskCapacity),
			"total_space_available":          fmt.Sprintf("%d", device.TotalSpaceAvailable),
			"video_disk_usage":               fmt.Sprintf("%d", device.VideoDiskUsage),
			"wifi_address":                   device.WifiAddress,
		})
	}
	return results
}

func CfgutilGetGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	var results []map[string]string
	ecidList := processContextConstraints(queryContext)
	cmdExecutor := CmdExecutor{}
	status, err := getCommandOutput(cmdExecutor, false, ecidList...)
	if err != nil {
		fmt.Println(err)
		return results, err
	}

	results = marshalCfgutilGet(status)

	return results, nil
}

func processContextConstraints(queryContext table.QueryContext) []string {
	ecidList := []string{}
	if constraintList, present := queryContext.Constraints["ecid"]; present {
		// ecids are in the where clause, we can append these to cfgutil to focus the command
		// we may want to require this
		for _, constraint := range constraintList.Constraints {
			if constraint.Operator == table.OperatorEquals {
				ecidList = append(ecidList, constraint.Expression)
			}
		}
	}
	return ecidList
}
