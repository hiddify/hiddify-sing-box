// Ported from Xray-core v26.7.28 infra/conf/common.go (Mozilla Public License 2.0).

package finalmask

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/common/errors"
)

// Int32Range deserializes from "1-2" or 1, so can deserialize from both int and number.
// Negative integers can be passed as sentinel values, but do not parse as ranges.
// Value will be exchanged if From > To, use .Left and .Right to get original value if need.
type Int32Range struct {
	Left  int32
	Right int32
	From  int32
	To    int32
}

// MarshalJSON implements encoding/json.Marshaler.MarshalJSON
func (v *Int32Range) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.String())
}

func (v Int32Range) String() string {
	if v.Left == v.Right {
		return strconv.Itoa(int(v.Left))
	} else {
		return fmt.Sprintf("%d-%d", v.Left, v.Right)
	}
}

// UnmarshalJSON implements encoding/json.Unmarshaler.UnmarshalJSON
func (v *Int32Range) UnmarshalJSON(data []byte) error {
	defer v.ensureOrder()
	var str string
	var rawint int32
	if err := json.Unmarshal(data, &str); err == nil {
		left, right, err := ParseRangeString(str)
		if err == nil {
			v.Left, v.Right = int32(left), int32(right)
			return nil
		}
	} else if err := json.Unmarshal(data, &rawint); err == nil {
		v.Left = rawint
		v.Right = rawint
		return nil
	}

	return errors.New("Invalid integer range, expected either string of form \"1-2\" or plain integer.")
}

// ensureOrder() gives value to .From & .To and make sure .From < .To
func (r *Int32Range) ensureOrder() {
	r.From, r.To = r.Left, r.Right
	if r.From > r.To {
		r.From, r.To = r.To, r.From
	}
}

// "-114-514"   →  ["-114","514"]
// "-1919--810" →  ["-1919","-810"]
func splitFromSecondDash(s string) []string {
	parts := strings.SplitN(s, "-", 3)
	if len(parts) < 3 {
		return []string{s}
	}
	return []string{parts[0] + "-" + parts[1], parts[2]}
}

// Parse rang in string. Support negative number.
// eg: "114-514" "-114-514" "-1919--810" "114514" ""(return 0)
func ParseRangeString(str string) (int, int, error) {
	// for number in string format like "114" or "-1"
	if value, err := strconv.Atoi(str); err == nil {
		return value, value, nil
	}
	// for empty "", we treat it as 0
	if str == "" {
		return 0, 0, nil
	}
	// for range value, like "114-514"
	var pair []string
	// Process sth like "-114-514" "-1919--810"
	if strings.HasPrefix(str, "-") {
		pair = splitFromSecondDash(str)
	} else {
		pair = strings.SplitN(str, "-", 2)
	}
	if len(pair) == 2 {
		left, err := strconv.Atoi(pair[0])
		right, err2 := strconv.Atoi(pair[1])
		if err == nil && err2 == nil {
			return left, right, nil
		}
	}
	return 0, 0, errors.New("invalid range string: ", str)
}
