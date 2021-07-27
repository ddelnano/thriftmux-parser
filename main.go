package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
	if handle, err := pcap.OpenOffline("./mux.pcap"); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			if err := handlePacket(packet); err != nil {
				fmt.Printf("Failed to handlePacket with error: %v\n", err)
			}
		}
	}

}

type MuxPacket struct {
	SizeHeader uint32
	Type       int8
	tag        [3]int8
	discardTag [3]int8
	Why        []byte
	NumCtx     uint16
	Ctx        map[string]map[string]interface{}
}

func (m MuxPacket) Tag() uint32 {
	return uint32(m.tag[0])<<16 | uint32(m.tag[1])<<8 | uint32(m.tag[2])
}

func (m MuxPacket) DiscardTag() uint32 {
	return uint32(m.discardTag[0])<<16 | uint32(m.discardTag[1])<<8 | uint32(m.discardTag[2])
}

func handlePacket(packet gopacket.Packet) error {
	// fmt.Println(packet.Dump())
	layer := packet.ApplicationLayer()

	// This packet doesn't contain any mux information
	if layer == nil {
		return nil
	}
	fmt.Println(gopacket.LayerDump(layer))
	// payload := layer.Payload()
	mux := &MuxPacket{}
	r := bytes.NewReader(layer.Payload())
	// if err := struc.Unpack(r, mux); err != nil {
	// 	return
	// }

	err := binary.Read(r, binary.BigEndian, &mux.SizeHeader)
	if err != nil {
		return err
	}

	err = binary.Read(r, binary.BigEndian, &mux.Type)
	if err != nil {
		return err
	}

	err = binary.Read(r, binary.BigEndian, &mux.tag)
	if err != nil {
		return err
	}

	// TODO: This isn't working yet
	if mux.Type == 127 || mux.Type == -128 {
		err = binary.Read(r, binary.BigEndian, &mux.Why)
		if err != nil {
			return err
		}
	}

	// TODO: This is untested at the moment
	if mux.Type == 66 || mux.Type == -62 {
		err = binary.Read(r, binary.BigEndian, &mux.discardTag)
		if err != nil {
			return err
		}

		// TODO: "Why" should be read after this
	}

	if mux.Type == 2 {
		err = binary.Read(r, binary.BigEndian, &mux.NumCtx)
		if err != nil {
			return err
		}

		context := map[string]map[string]interface{}{}
		for i := 0; i < int(mux.NumCtx); i++ {
			var ctxKeyLen uint16
			err = binary.Read(r, binary.BigEndian, &ctxKeyLen)
			if err != nil {
				return err
			}

			ctxKey, err := ioutil.ReadAll(io.LimitReader(r, int64(ctxKeyLen)))

			if err != nil {
				return err
			}

			var ctxValueLen uint16
			err = binary.Read(r, binary.BigEndian, &ctxValueLen)
			if err != nil {
				return err
			}

			ctxValueBytes, err := ioutil.ReadAll(io.LimitReader(r, int64(ctxValueLen)))

			if err != nil {
				return err
			}

			ctxValue, err := decodeCtx(string(ctxKey), ctxValueBytes)

			if err != nil {
				return err
			}

			context[string(ctxKey)] = ctxValue
		}
		mux.Ctx = context

		// TODO: Need to update to parse dest and dtabs
	}

	fmt.Printf("Size header: %d Type: %d Tag: %v Why: %s NumCtx: %d Ctx: %v\n", mux.SizeHeader, mux.Type, mux.Tag(), string(mux.Why), mux.NumCtx, mux.Ctx)
	return nil
}

func decodeCtx(ctxKey string, ctxValue []byte) (map[string]interface{}, error) {
	switch ctxKey {
	case "com.twitter.finagle.Deadline":
		// 8 bytes for timestamp
		// 8 bytes for deadline
		return map[string]interface{}{
			"timestamp": binary.BigEndian.Uint64(ctxValue[0:8]) / 1000,
			"deadline":  binary.BigEndian.Uint64(ctxValue[8:16]) / 1000,
		}, nil
	case "com.twitter.finagle.tracing.TraceContext":
		// 8 bytes for span id
		// 8 bytes for parent id
		// 8 bytes for trace id
		// 8 bytes for flags
		return map[string]interface{}{
			"span id":   binary.BigEndian.Uint64(ctxValue[0:8]),
			"parent id": binary.BigEndian.Uint64(ctxValue[8:16]),
			"trace id":  binary.BigEndian.Uint64(ctxValue[16:24]),
			"flags":     binary.BigEndian.Uint64(ctxValue[24:32]),
		}, nil
	case "com.twitter.finagle.thrift.ClientIdContext":
		// utf-8 string
		// TODO: This needs to be validated
		return map[string]interface{}{
			"name": string(ctxValue),
		}, nil
	}

	return map[string]interface{}{
		"length": len(ctxValue),
	}, nil
}
