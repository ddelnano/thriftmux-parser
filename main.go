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

const (
	ThriftBool = iota + 2
	ThriftByte
	ThriftDouble
	_
	ThriftI16
	_
	ThriftI32
	_
	ThriftI64
	ThriftString
	ThriftStruct
	ThriftMap
	ThriftSet
	ThriftList
)

const (
	Treq = 1
	Rreq = -1

	Tdispatch = 2
	Rdispatch = -2

	// control messages
	Tdrain = 64
	Rdrain = -64
	Tping  = 65
	Rping  = -65

	Tdiscarded = 66
	Rdiscarded = -66

	Tlease = 67

	Tinit = 68
	Rinit = -68

	Rerr = -128

	// only used to preserve backwards compatibility
	TdiscardedOld = -62
	RerrOld       = 127
)

const (
	MuxReplyOk = iota
	MuxReplyError
	MuxReplyNack
)

func main() {
	if handle, err := pcap.OpenOffline("./mux.pcap"); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		muxParser := MuxParser{
			ApplicationProto: ThriftParser{},
		}
		for packet := range packetSource.Packets() {
			if err := muxParser.Parse(packet); err != nil {
				fmt.Printf("Failed to parse mux packet with error: %v\n", err)
			}
		}
	}

}

type MuxPacket struct {
	SizeHeader  uint32
	Type        int8
	tag         [3]int8
	discardTag  [3]int8
	Why         string
	NumCtx      uint16
	Ctx         map[string]map[string]interface{}
	Dest        string
	Dtabs       map[string]string
	ReplyStatus uint8
}

func (m MuxPacket) Tag() uint32 {
	return uint32(m.tag[0])<<16 | uint32(m.tag[1])<<8 | uint32(m.tag[2])
}

type ProtoParser interface {
	Parse(r *bytes.Reader) error
}

type ThriftParser struct {
}

type ThriftPayload struct {
	Version     uint16
	MessageType int
	Name        string
	SequenceId  int32
}

func (p ThriftParser) Parse(r *bytes.Reader) error {
	l := r.Len()
	if l < 12 {
		fmt.Printf("Payload too small to contain thrift data\n\n")
		return nil
	}

	var version uint16
	err := binary.Read(r, binary.BigEndian, &version)
	if err != nil {
		return err
	}

	// int(v) xor 0x80 == 1
	if version != 0x8001 {
		fmt.Printf("Payload does not conform to thrift standard: %d\n", version)
		return nil
	}

	// unused byte as per thrift spec
	r.ReadByte()

	// Read entire byte, but we are only interested in the 3 bit int
	msgType, err := r.ReadByte()
	if err != nil {
		return err
	}

	fmt.Printf("Found thrift message of type: %v\n", int(msgType))

	var nameLen int32
	err = binary.Read(r, binary.BigEndian, &nameLen)
	if err != nil {
		return err
	}

	name, err := ioutil.ReadAll(io.LimitReader(r, int64(nameLen)))
	if err != nil {
		return err
	}

	var seqId int32
	err = binary.Read(r, binary.BigEndian, &seqId)
	if err != nil {
		return err
	}

	fmt.Printf("Found thrift name length: %d name: %s seq id: %d\n", nameLen, string(name), seqId)

	for {
		var fieldType uint8
		err = binary.Read(r, binary.BigEndian, &fieldType)
		if err != nil {
			return err
		}

		if fieldType == 0 {
			break
		}

		// fieldId
		var fieldId int16
		err = binary.Read(r, binary.BigEndian, &fieldId)
		if err != nil {
			return err
		}

		fmt.Printf("Found field type: %d and ID: %d\n", fieldType, fieldId)

		switch fieldType {

		case ThriftString:
			// even though this is signed it's expected to be >= 0
			var strLen int32
			if err := binary.Read(r, binary.BigEndian, &strLen); err != nil {
				return err
			}

			strData, err := ioutil.ReadAll(io.LimitReader(r, int64(strLen)))
			if err != nil {
				return err
			}
			fmt.Printf("Found string: %s\n", string(strData))

		case ThriftBool:
			fallthrough
		case ThriftByte:
			fallthrough
		case ThriftDouble:
			fallthrough
		case ThriftI16:
			fallthrough
		case ThriftI32:
			fallthrough
		case ThriftI64:
			fallthrough
		case ThriftStruct:
			fallthrough
		case ThriftMap:
			fallthrough
		case ThriftSet:
			fallthrough
		case ThriftList:
			fallthrough
		default:
			panic(fmt.Sprintf("Field type %d not implemented", fieldType))
		}
	}

	fmt.Println("Finished parsing thrift message")
	return nil
}

type NullParser struct{}

func (p NullParser) Parse(r *bytes.Reader) error {
	return nil
}

type MuxParser struct {
	ApplicationProto ProtoParser
}

func (p MuxParser) Parse(packet gopacket.Packet) error {

	layer := packet.ApplicationLayer()

	// This packet doesn't contain any mux information
	if layer == nil {
		return nil
	}

	fmt.Println(gopacket.LayerDump(layer))
	mux := &MuxPacket{}
	r := bytes.NewReader(layer.Payload())

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

	if mux.Type == RerrOld || mux.Type == -128 {
		why, err := ioutil.ReadAll(r)
		if err != nil {
			return err
		}
		mux.Why = string(why)
	}

	if mux.Type == Rdispatch {
		if err := binary.Read(r, binary.BigEndian, &mux.ReplyStatus); err != nil {
			return err
		}
	}

	if mux.Type == Tdispatch || mux.Type == Rdispatch {
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

		if mux.NumCtx == 0 {
			return p.ApplicationProto.Parse(r)
		}
		mux.Ctx = context

		// TODO: Dest parsing is untested at this point
		var destLen uint16
		err = binary.Read(r, binary.BigEndian, &destLen)
		if err != nil {
			return err
		}

		dest, err := ioutil.ReadAll(io.LimitReader(r, int64(destLen)))

		if err != nil {
			return err
		}

		mux.Dest = string(dest)

		// TODO: dtab parsing is untested at this point
		var numDtabs uint16
		err = binary.Read(r, binary.BigEndian, &numDtabs)
		if err != nil {
			return err
		}

		dtabs := map[string]string{}
		for i := 0; i < int(numDtabs); i++ {
			var srcLen uint16

			err := binary.Read(r, binary.BigEndian, &srcLen)
			if err != nil {
				return err
			}

			src, err := ioutil.ReadAll(io.LimitReader(r, int64(srcLen)))
			if err != nil {
				return err
			}

			var destLen uint16

			err = binary.Read(r, binary.BigEndian, &destLen)
			if err != nil {
				return err
			}

			dest, err := ioutil.ReadAll(io.LimitReader(r, int64(destLen)))
			if err != nil {
				return err
			}

			dtabs[string(src)] = string(dest)
		}

		mux.Dtabs = dtabs
	}

	fmt.Printf("Size header: %d Type: %d Tag: %v Why: %s NumCtx: %d Ctx: %v Dest: %s Dtabs: %v Payload length: %d\n", mux.SizeHeader, mux.Type, mux.Tag(), string(mux.Why), mux.NumCtx, mux.Ctx, mux.Dest, mux.Dtabs, r.Len())

	return p.ApplicationProto.Parse(r)
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
		// TODO: This has not been tested
		return map[string]interface{}{
			"name": string(ctxValue),
		}, nil
	}

	return map[string]interface{}{
		"length": len(ctxValue),
	}, nil
}
