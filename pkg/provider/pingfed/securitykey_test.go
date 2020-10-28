package pingfed

//func TestProcessRequest(t *testing.T) {
//	req := requestInput{
//		Challenge: nil,
//		Timeout:   50,
//		RpId:      "ttt",
//		AllowCredentials: []credentialInput{
//			{
//				Type: "rsa",
//				ID:   nil,
//			},
//		},
//		UserVerification: "yes",
//	}
//	resp := processRequest(req)
//
//	expected := parsedRequest{
//		Challenge: "",
//		Timeout:   50,
//		RpId:      "ttt",
//		AllowCredentials: []parsedCredential{
//			{
//				ID:   "1",
//				Type: "rsa",
//			},
//		},
//		UserVerification: "yes",
//	}
//
//	require.Equal(t, expected, resp)
//}
