//go:build go1.19

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"reflect"
	"unsafe"
)

const (
	BLOCK_AES = 10
)

var (
	supportAES    = false
	supportsGFMUL = false
)

func init() {
	cipher, _ := aes.NewCipher(make([]byte, 16))
	if reflect.ValueOf(cipher).Elem().Type().String() == "aes.aesCipherGCM" {
		supportAES = true
		supportsGFMUL = true
	} else if reflect.ValueOf(cipher).Elem().Field(0).Type().String() == "aes.aesCipherAsm" {
		supportAES = true
	} else {
		supportAES = false
	}
}

type aesCipher struct {
	enc []uint32
	dec []uint32
}

func dump(blk cipher.Block) (any, error) {
	// type aesCipherGCM struct {
	//   type aesCipherAsm struct {
	//    aesCipher struct {
	//      enc []uint32
	//      dec []uint32
	//    }
	//  }
	//}
	cipher := reflect.ValueOf(blk).Elem()
	if cipher.Type().String() == "aes.aesCipherGCM" {
		cipher = cipher.Field(0)
	}
	if cipher.Type().String() == "aes.aesCipherAsm" {
		cipher = cipher.Field(0)
	}
	if cipher.Type().String() == "aes.aesCipher" {
		enc := getUnexportedField(cipher.Field(0)).([]uint32)
		dec := getUnexportedField(cipher.Field(1)).([]uint32)
		return &aesCipher{enc, dec}, nil
	}
	return nil, fmt.Errorf("unsupported cipher type: %s", reflect.ValueOf(blk).Type().String())
}

// from https://stackoverflow.com/a/60598827
func getUnexportedField(field reflect.Value) interface{} {
	return reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Interface()
}

func setUnexportedField(field reflect.Value, value interface{}) {
	reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).
		Elem().
		Set(reflect.ValueOf(value))
}
