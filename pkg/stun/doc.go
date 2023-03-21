// This is an implementation of RFC5389 with some additional stuff to support
// TURN (RFC5766 version) messages
// References:
// https://datatracker.ietf.org/doc/html/rfc5389
// https://datatracker.ietf.org/doc/html/rfc5766
// https://www.rfc-editor.org/rfc/rfc3489
// General packet structure
//
//
//   0               1               2               3               4
//   0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0
//  0+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |0 0|     STUN Message Type     |         Message Length        |
//  4+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                         Magic Cookie                          |
//  8+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                                                               |
//   |                     Transaction ID (96 bits)                  |
//   |                                                               |
// 20+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                                                               |
//   /                     0 or more Attributes                      /
//   |                                                               |
// XX+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//   Magic Cookie is 0x2112A442 (https://www.slideshare.net/GiacomoVacca/stun-protocol)
//
//   Transaction ID is defined by the client as opposed to the server
//
//	 Message Length ignores the 20 bytes in the header :)
//
//   STUN messages have a value 0x0000 through 0x3FFF
//   TURN messages have a value 0x4000 through 0x7FFF
//
//   STUN message types
//   0x0001 - Binding Request
//   0x0101 - Binding Response
//   0x0111 - Binding Error Response
//   0x0002 - Shared Secret Request
//   0x0102 - Shared Secret Response
//   0x0112 - Shared Secret Error Response
//
//   Additional STUN message types introduced by TURN
//   (All have request/response semantics defined)
//   0x0003 - Allocate Request
//   0x0103 - Allocate Response Success
//   0x0113 - Allocate Response Error
//   0x0004 - Refresh Request
//   0x0104 - Refresh Response Success
//   0x0114 - Refresh Response Error
//   0x0006 - Send Request
//   0x0106 - Send Response Success
//   0x0116 - Send Response Error
//   0x0007 - Data Request
//   0x0107 - Data Response Success
//   0x0117 - Data Response Error
//   0x0008 - CreatePermission Request
//   0x0108 - CreatePermission Response Success
//   0x0118 - CreatePermission Response Error
//   0x0009 - ChannelBind Request
//   0x0109 - ChannelBind Response Success
//   0x0119 - ChannelBind Response Error
//
//   Attributes
//
//   General packet structure
//   0               1               2               3               4
//   0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0
//  0+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |         Type                  |            Length             |
//  4+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                             Value                             ....
// XX+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//
//  Attribute Types (RFC5389)
//  0x0001 MAPPED-ADDRESS
//  0x0002 (RESERVED)
//  0x0003 (RESERVED)
//  0x0004 (RESERVED)
//  0x0005 (RESERVED)
//  0x0006 USERNAME
//  0x0007 (RESERVED)
//  0x0008 MESSAGE-INTEGRITY
//  0x0009 ERROR-CODE
//  0x000A UNKNOWN-ATTRIBUTES
//  0x000B (RESERVED)
//  0x0014 Realm
//  0x0015 Nonce
//  0x0020 XOR-MAPPED-ADDRESS
//
//  Comprehension-optional range
//  0x8022 Software
//  0x8023 Alternative Server
//  0x8028 Fingerprint
//
//  Attribute Types (RFC5766)
//  0x000C CHANNEL-NUMBER
//  0x000D LIFETIME
//  0x0010 Reserved (was BANDWIDTH)
//  0x0012 XOR-PEER-ADDRESS
//  0x0013 DATA
//  0x0016 XOR-RELAYED-ADDRESS
//  0x0018 EVEN-PORT
//  0x0019 REQUESTED-TRANSPORT
//  0x001A DONT-FRAGMENT
//  0x0021 Reserved (was TIMER-VAL)
//  0x0022 RESERVATION-TOKEN
package stun
