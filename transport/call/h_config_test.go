package call

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// an unknown wbstream mode is refused instead of never connecting
func TestH_ConnectWBStreamMode(t *testing.T) {
	_, err := Connect(context.Background(), Config{Platform: "wbstream", Mode: "audio", Role: RoleJoiner, JoinLink: "x"})
	require.ErrorContains(t, err, "unknown wbstream mode")
}
