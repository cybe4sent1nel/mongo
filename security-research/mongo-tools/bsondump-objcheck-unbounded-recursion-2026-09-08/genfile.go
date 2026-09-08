//go:build ignore

package main

import (
	"encoding/binary"
	"os"
	"strconv"
)

func buildNestedDoc(depth int) []byte {
	total := 5 + 8*depth
	buf := make([]byte, total)
	for k := 0; k < depth; k++ {
		off := k * 7
		lenK := uint32(5 + 8*(depth-k))
		binary.LittleEndian.PutUint32(buf[off:], lenK)
		buf[off+4] = 0x03
		buf[off+5] = 'a'
		buf[off+6] = 0x00
	}
	innerOff := depth * 7
	binary.LittleEndian.PutUint32(buf[innerOff:], 5)
	buf[innerOff+4] = 0x00
	return buf
}

func main() {
	depth := 2000000
	if len(os.Args) > 2 {
		d, _ := strconv.Atoi(os.Args[2])
		depth = d
	}
	os.WriteFile(os.Args[1], buildNestedDoc(depth), 0644)
}
