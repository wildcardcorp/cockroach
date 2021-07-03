// Code generated by "stringer -type=ClientMessageType"; DO NOT EDIT.

package pgwirebase

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[ClientMsgBind-66]
	_ = x[ClientMsgClose-67]
	_ = x[ClientMsgCopyData-100]
	_ = x[ClientMsgCopyDone-99]
	_ = x[ClientMsgCopyFail-102]
	_ = x[ClientMsgDescribe-68]
	_ = x[ClientMsgExecute-69]
	_ = x[ClientMsgFlush-72]
	_ = x[ClientMsgParse-80]
	_ = x[ClientMsgPassword-112]
	_ = x[ClientMsgSimpleQuery-81]
	_ = x[ClientMsgSync-83]
	_ = x[ClientMsgTerminate-88]
}

const (
	_ClientMessageType_name_0 = "ClientMsgBindClientMsgCloseClientMsgDescribeClientMsgExecute"
	_ClientMessageType_name_1 = "ClientMsgFlush"
	_ClientMessageType_name_2 = "ClientMsgParseClientMsgSimpleQuery"
	_ClientMessageType_name_3 = "ClientMsgSync"
	_ClientMessageType_name_4 = "ClientMsgTerminate"
	_ClientMessageType_name_5 = "ClientMsgCopyDoneClientMsgCopyData"
	_ClientMessageType_name_6 = "ClientMsgCopyFail"
	_ClientMessageType_name_7 = "ClientMsgPassword"
)

var (
	_ClientMessageType_index_0 = [...]uint8{0, 13, 27, 44, 60}
	_ClientMessageType_index_2 = [...]uint8{0, 14, 34}
	_ClientMessageType_index_5 = [...]uint8{0, 17, 34}
)

func (i ClientMessageType) String() string {
	switch {
	case 66 <= i && i <= 69:
		i -= 66
		return _ClientMessageType_name_0[_ClientMessageType_index_0[i]:_ClientMessageType_index_0[i+1]]
	case i == 72:
		return _ClientMessageType_name_1
	case 80 <= i && i <= 81:
		i -= 80
		return _ClientMessageType_name_2[_ClientMessageType_index_2[i]:_ClientMessageType_index_2[i+1]]
	case i == 83:
		return _ClientMessageType_name_3
	case i == 88:
		return _ClientMessageType_name_4
	case 99 <= i && i <= 100:
		i -= 99
		return _ClientMessageType_name_5[_ClientMessageType_index_5[i]:_ClientMessageType_index_5[i+1]]
	case i == 102:
		return _ClientMessageType_name_6
	case i == 112:
		return _ClientMessageType_name_7
	default:
		return "ClientMessageType(" + strconv.FormatInt(int64(i), 10) + ")"
	}
}
