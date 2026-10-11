// SPDX-License-Identifier: GPL-3.0-or-later
package awg

import (
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

// UAPI itself accepts unbounded junk counts and negative I-packet lengths.
// Validate them before upstream starts background handshake goroutines.
func validateParameters(values map[string]string, mtu int) error {
	invalid := errors.New("invalid AWG obfuscation limits")
	var junkCount, junkMin, junkMax uint64
	for key, value := range values {
		if key == "header_protection_key" {
			continue
		}
		if len(key) == 2 && key[0] == 'i' {
			if !validIPacket(value) {
				return invalid
			}
			continue
		}
		minimum, maximum, ok := unsignedRange(value)
		if !ok {
			return invalid
		}
		switch key {
		case "jc", "jmin", "jmax", "s1", "s2", "s3", "s4":
			if minimum != maximum || maximum > 65000 {
				return invalid
			}
			if key == "jc" {
				if maximum > 128 {
					return invalid
				}
				junkCount = maximum
			}
			if key == "jmin" {
				junkMin = maximum
			}
			if key == "jmax" {
				junkMax = maximum
			}
			if key == "s4" && maximum+uint64(mtu)+80 > 65535 {
				return invalid
			}
		case "content_padding_addition":
			if maximum > uint64(mtu) {
				return invalid
			}
		case "max_handshake_attempts":
			if maximum > 1024 {
				return invalid
			}
		}
	}
	if junkMin > junkMax || junkCount*junkMax > 1<<20 {
		return invalid
	}
	return nil
}

func unsignedRange(value string) (uint64, uint64, bool) {
	parts := strings.Split(value, "-")
	if len(parts) < 1 || len(parts) > 2 {
		return 0, 0, false
	}
	first, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return 0, 0, false
	}
	last := first
	if len(parts) == 2 {
		last, err = strconv.ParseUint(parts[1], 10, 32)
		if err != nil || last < first {
			return 0, 0, false
		}
	}
	return first, last, true
}

func validIPacket(spec string) bool {
	remaining, total, tags := strings.TrimSpace(spec), 0, 0
	for remaining != "" {
		if !strings.HasPrefix(remaining, "<") {
			return false
		}
		end := strings.IndexByte(remaining, '>')
		if end < 0 {
			return false
		}
		parts := strings.Fields(remaining[1:end])
		if len(parts) == 0 || len(parts) > 2 {
			return false
		}
		argument := ""
		if len(parts) == 2 {
			argument = parts[1]
		}
		switch parts[0] {
		case "b":
			data, err := hex.DecodeString(strings.TrimPrefix(argument, "0x"))
			if err != nil || len(data) == 0 {
				return false
			}
			total += len(data)
		case "t":
			if argument != "" {
				return false
			}
			total += 4
		case "r", "rc", "rd", "dz":
			number, err := strconv.ParseUint(argument, 10, 16)
			if err != nil {
				return false
			}
			total += int(number)
		case "d", "ds":
			if argument != "" {
				return false
			}
		default:
			return false
		}
		tags++
		if total > 65000 || tags > 256 {
			return false
		}
		remaining = strings.TrimSpace(remaining[end+1:])
	}
	return tags > 0
}
