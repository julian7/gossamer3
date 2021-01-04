package pingfed

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProcessRequest(t *testing.T) {
	req := requestInput{
		Challenge: []int64{0, 0, -37, 64, 28, -72, 63, 42, 42, 58, 11, -34, -48, -45, -101, -58, -8, -92, 0, -43, 22, -72, 54, 48, 117, 27, 106, 41, 76, 120, 49, 15},
		Timeout:   50,
		RpId:      "ttt",
		AllowCredentials: []credentialInput{
			{
				Type: "rsa",
				ID:   []int64{51, -59, -54, 26, -112, -1, 26, -108, -84, -63, -45, -79, 99, 23, -115, -125, -36, 31, 72, 18, 92, -22, 1, -8, -127, 10, 30, 13, 118, 33, 126, 47, 24, 86, 20, 126, -37, 10, -62, -24, -47, 3, 2, -7, 86, -12, -73, -56, 0, -1, -128, -29, 36, 27, 32, -39, -78, 72, -89, 39, 90, -128, -93, -89},
			},
		},
		UserVerification: "yes",
	}
	resp := processRequest(req)

	expected := parsedRequest{
		Challenge: "AADbQBy4PyoqOgve0NObxvikANUWuDYwdRtqKUx4MQ8",
		Timeout:   50,
		RpId:      "ttt",
		AllowCredentials: []parsedCredential{
			{
				ID:   "M8XKGpD_GpSswdOxYxeNg9wfSBJc6gH4gQoeDXYhfi8YVhR-2wrC6NEDAvlW9LfIAP-A4yQbINmySKcnWoCjpw",
				Type: "rsa",
			},
		},
		UserVerification: "yes",
	}

	require.Equal(t, expected, resp)
}
