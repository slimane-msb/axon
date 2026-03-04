package tests

import (
    "encoding/binary"
    "testing"
)

// ParseSNIFromClientHello extracts the Server Name Indication from a TLS Client Hello.
// Note: I renamed it to start with a Capital so other tests can see it if needed.
func ParseSNIFromClientHello(hello []byte) string {
    if len(hello) < 38 {
        return ""
    }
    offset := 2  // Skip Version
    offset += 32 // Skip Random

    if offset >= len(hello) {
        return ""
    }
    sessionIDLen := int(hello[offset])
    offset += 1 + sessionIDLen

    if offset+2 > len(hello) {
        return ""
    }
    cipherLen := int(binary.BigEndian.Uint16(hello[offset : offset+2]))
    offset += 2 + cipherLen

    if offset+1 > len(hello) {
        return ""
    }
    compLen := int(hello[offset])
    offset += 1 + compLen

    if offset+2 > len(hello) {
        return ""
    }
    
    // Skip Extensions Length (2 bytes)
    offset += 2

    for offset+4 <= len(hello) {
        extType := binary.BigEndian.Uint16(hello[offset : offset+2])
        extLen := int(binary.BigEndian.Uint16(hello[offset+2 : offset+4]))
        offset += 4

        if offset+extLen > len(hello) {
            break
        }

        // extType 0 is SNI
        if extType == 0 && extLen > 5 {
            extData := hello[offset : offset+extLen]
            // extData[2] == 0 is name_type host_name
            if extData[2] == 0 {
                nameLen := int(binary.BigEndian.Uint16(extData[3:5]))
                if 5+nameLen <= len(extData) {
                    return string(extData[5 : 5+nameLen])
                }
            }
        }
        offset += extLen
    }
    return ""
}

func TestParseSNI(t *testing.T) {
    // Helper to build a valid ClientHello for testing
    buildHello := func(host string) []byte {
        sniBytes := []byte(host)
        n := len(sniBytes)
        // SNI Extension: Type(2), ExtLen(2), ListLen(2), NameType(1), NameLen(2), Name(n)
        sniExt := []byte{0x00, 0x00, byte((n + 5) >> 8), byte(n + 5), byte((n + 3) >> 8), byte(n + 3), 0x00, byte(n >> 8), byte(n)}
        sniExt = append(sniExt, sniBytes...)

        hello := []byte{0x03, 0x03}                // Version
        hello = append(hello, make([]byte, 32)...) // Random
        hello = append(hello, 0x00)                // Session ID len
        hello = append(hello, 0x00, 0x02, 0x00, 0x2f) // Cipher suites
        hello = append(hello, 0x01, 0x00)          // Compression
        
        extLen := len(sniExt)
        hello = append(hello, byte(extLen>>8), byte(extLen))
        hello = append(hello, sniExt...)
        return hello
    }

    // Table-driven test cases
    tests := []struct {
        name     string
        input    []byte
        expected string
    }{
        {"Valid SNI", buildHello("axon.example.com"), "axon.example.com"},
        {"Empty Input", []byte{}, ""},
        {"Too Short", make([]byte, 10), ""},
        {"No Extensions", []byte{0x03, 0x03 /* ... more padding ... */}, ""},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got := ParseSNIFromClientHello(tt.input)
            if got != tt.expected {
                t.Errorf("ParseSNIFromClientHello() = %q, want %q", got, tt.expected)
            }
        })
    }
}