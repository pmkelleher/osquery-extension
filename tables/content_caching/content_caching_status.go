package content_caching

import (
	"context"
	"fmt"
	"strings"

	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/osquery/osquery-go/plugin/table"
)

func CCStatusColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.IntegerColumn("activated"),
		table.IntegerColumn("active"),
		table.BigIntColumn("actual_cache_used"),
		table.BigIntColumn("cache_apple_tv_software"),
		table.BigIntColumn("cache_icloud"),
		table.BigIntColumn("cache_ios_software"),
		table.BigIntColumn("cache_mac_software"),
		table.BigIntColumn("cache_other"),
		table.BigIntColumn("cache_free"),
		table.BigIntColumn("cache_limit"),
		table.TextColumn("cache_status"),
		table.BigIntColumn("cache_used"),
		table.BigIntColumn("personal_cache_free"),
		table.BigIntColumn("personal_cache_limit"),
		table.BigIntColumn("personal_cache_used"),
		table.IntegerColumn("port"),
		table.TextColumn("private_addresses"),
		table.TextColumn("public_address"),
		table.IntegerColumn("registration_status"),
		table.IntegerColumn("restricted_media"),
		table.TextColumn("server_guid"),
		table.TextColumn("startup_status"),
		table.IntegerColumn("tetherator_status"),
		table.TextColumn("total_bytes_are_since"),
		table.BigIntColumn("total_bytes_dropped"),
		table.BigIntColumn("total_bytes_imported"),
		table.BigIntColumn("total_bytes_returned_to_children"),
		table.BigIntColumn("total_bytes_returned_to_clients"),
		table.BigIntColumn("total_bytes_returned_to_peers"),
		table.BigIntColumn("total_bytes_stored_from_origin"),
		table.BigIntColumn("total_bytes_stored_from_parents"),
		table.BigIntColumn("total_bytes_stored_from_peers"),
	}
}

func marshalCCStatus(commandOutput CommandOutput) []map[string]string {
	var results []map[string]string

	// transform private addresses array into single comma seperated string
	privateAddresses := strings.Join(commandOutput.Result.PrivateAddresses, ",")

	results = append(results, map[string]string{
		"activated":                        BoolToString(commandOutput.Result.Activated),
		"active":                           BoolToString(commandOutput.Result.Active),
		"actual_cache_used":                IntToString(commandOutput.Result.ActualCacheUsed),
		"cache_apple_tv_software":          IntToString(commandOutput.Result.CacheDetails.AppleTVSoftware),
		"cache_icloud":                     IntToString(commandOutput.Result.CacheDetails.ICloud),
		"cache_ios_software":               IntToString(commandOutput.Result.CacheDetails.IOSSoftware),
		"cache_mac_software":               IntToString(commandOutput.Result.CacheDetails.MacSoftware),
		"cache_other":                      IntToString(commandOutput.Result.CacheDetails.Other),
		"cache_free":                       IntToString(commandOutput.Result.CacheFree),
		"cache_limit":                      IntToString(commandOutput.Result.CacheLimit),
		"cache_status":                     commandOutput.Result.CacheStatus,
		"cache_used":                       IntToString(commandOutput.Result.CacheUsed),
		"personal_cache_free":              IntToString(commandOutput.Result.PersonalCacheFree),
		"personal_cache_limit":             IntToString(commandOutput.Result.PersonalCacheLimit),
		"personal_cache_used":              IntToString(commandOutput.Result.PersonalCacheUsed),
		"port":                             IntToString(commandOutput.Result.Port),
		"private_addresses":                privateAddresses,
		"public_address":                   commandOutput.Result.PublicAddress,
		"registration_status":              IntToString(commandOutput.Result.RegistrationStatus),
		"restricted_media":                 BoolToString(commandOutput.Result.RestrictedMedia),
		"server_guid":                      commandOutput.Result.ServerGUID,
		"startup_status":                   commandOutput.Result.StartupStatus,
		"tetherator_status":                IntToString(commandOutput.Result.TetheratorStatus),
		"total_bytes_are_since":            IntToString(commandOutput.Result.TotalBytesAreSince),
		"total_bytes_dropped":              IntToString(commandOutput.Result.TotalBytesDropped),
		"total_bytes_imported":             IntToString(commandOutput.Result.TotalBytesImported),
		"total_bytes_returned_to_children": IntToString(commandOutput.Result.TotalBytesReturnedToChildren),
		"total_bytes_returned_to_clients":  IntToString(commandOutput.Result.TotalBytesReturnedToClients),
		"total_bytes_returned_to_peers":    IntToString(commandOutput.Result.TotalBytesReturnedToPeers),
		"total_bytes_stored_from_origin":   IntToString(commandOutput.Result.TotalBytesStoredFromOrigin),
		"total_bytes_stored_from_parents":  IntToString(commandOutput.Result.TotalBytesStoredFromParents),
		"total_bytes_stored_from_peers":    IntToString(commandOutput.Result.TotalBytesStoredFromPeers),
	})

	return results
}

func CCStatusGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	var results []map[string]string
	cmdExecutor := utils.NewRunner()
	status, err := getCommandOutput(cmdExecutor)
	if err != nil {
		fmt.Println(err)
		return results, err
	}

	results = marshalCCStatus(status)

	return results, nil
}
