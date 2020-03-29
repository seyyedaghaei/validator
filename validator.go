package validator

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var hashLengths = map[string]int{
	"md5":       32,
	"md4":       32,
	"sha1":      40,
	"sha256":    64,
	"sha384":    96,
	"sha512":    128,
	"ripemd128": 32,
	"ripemd160": 40,
	"tiger128":  32,
	"tiger160":  40,
	"tiger192":  48,
	"crc32":     8,
	"crc32b":    8,
}

func IsEmpty(str string) bool {
	return len(str) == 0
}

func IsPort(str string) bool {
	port, err := strconv.Atoi(str)
	return err == nil && 0 <= port && port <= 0xFFFF
}

func IsHash(str string, algorithm string) bool {
	return test(fmt.Sprintf("^[a-fA-F0-9]{%d}$", hashLengths[strings.ToLower(algorithm)]), str)
}

func IsJSON(str string) bool {
	var m map[string]interface{}
	return json.Unmarshal([]byte(str), &m) == nil

}

func IsBase64(str string) bool {
	size := len(str)
	if size == 0 || size%4 != 0 || test("[^A-Z0-9+\\\\/=]", str) {
		return false
	}
	firstPaddingChar := strings.Index(str, "=")
	return firstPaddingChar == -1 || firstPaddingChar == size-1 || firstPaddingChar == size-2 && str[size-1] == '='
}

func IsBase32(str string) bool {
	size := len(str)
	return size > 0 && size%8 == 0 && test("^[A-Z2-7]+=*$", str)
}

func IsJWT(str string) bool {
	return false
}

func IsLower(str string) bool {
	return str == strings.ToLower(str)
}

func IsUpper(str string) bool {
	return str == strings.ToUpper(str)
}

func IsASCII(str string) bool {
	return test("^[\\\\x00-\\\\x7F]+$", str)
}

func IsBIC(str string) bool {
	return test("^[A-z]{4}[A-z]{2}\\\\w{2}(\\\\w{3})?$", str)
}

func IsOctal(str string) bool {
	return test("^(0o)?[0-7]+$", str)
}

func IsHexadecimal(str string) bool {
	return test("^(0x|0h)?[0-9A-Fa-f]+$", str)
}

func IsMongoId(str string) bool {
	return IsHexadecimal(str) && len(str) == 24
}

func test(pattern string, str string) bool {
	return regexp.MustCompile(pattern).MatchString(str)
}

func IsBool(str string) bool {
	_, err := strconv.ParseBool(str)
	return err == nil
}
