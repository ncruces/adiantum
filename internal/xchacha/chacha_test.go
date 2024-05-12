// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// Originally from:
// https://github.com/aead/chacha20/tree/master/chacha

package xchacha

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func toHex(bits []byte) string {
	return hex.EncodeToString(bits)
}

func fromHex(bits string) []byte {
	b, err := hex.DecodeString(bits)
	if err != nil {
		panic(err)
	}
	return b
}

func TestVectors(t *testing.T) {
	defer func(sse2, ssse3, avx, avx2, vx bool) {
		useSSE2, useSSSE3, useAVX, useAVX2, useVX = sse2, ssse3, avx, avx2, vx
	}(useSSE2, useSSSE3, useAVX, useAVX2, useVX)

	if useAVX2 {
		t.Log("AVX2 version")
		testVectors(t)
		useAVX2 = false
	}
	if useAVX {
		t.Log("AVX version")
		testVectors(t)
		useAVX = false
	}
	if useSSSE3 {
		t.Log("SSSE3 version")
		testVectors(t)
		useSSSE3 = false
	}
	if useSSE2 {
		t.Log("SSE2 version")
		testVectors(t)
		useSSE2 = false
	}
	if useVX {
		t.Log("VX version")
		testVectors(t)
		useVX = false
	}
	t.Log("generic version")
	testVectors(t)
}

func TestIncremental(t *testing.T) {
	defer func(sse2, ssse3, avx, avx2, vx bool) {
		useSSE2, useSSSE3, useAVX, useAVX2, useVX = sse2, ssse3, avx, avx2, vx
	}(useSSE2, useSSSE3, useAVX, useAVX2, useVX)

	if useAVX2 {
		t.Log("AVX2 version")
		testIncremental(t, 5, 2049)
		useAVX2 = false
	}
	if useAVX {
		t.Log("AVX version")
		testIncremental(t, 5, 2049)
		useAVX = false
	}
	if useSSSE3 {
		t.Log("SSSE3 version")
		testIncremental(t, 5, 2049)
		useSSSE3 = false
	}
	if useSSE2 {
		t.Log("SSE2 version")
		testIncremental(t, 5, 2049)
	}
	if useVX {
		t.Log("VX version")
		testIncremental(t, 5, 2049)
	}
}

func testVectors(t *testing.T) {
	for i, v := range vectors {
		if len(v.plaintext) == 0 {
			v.plaintext = make([]byte, len(v.ciphertext))
		}

		dst := make([]byte, len(v.ciphertext))

		XORKeyStream(dst, v.plaintext, v.nonce, v.key, v.rounds)
		if !bytes.Equal(dst, v.ciphertext) {
			t.Errorf("Test %d: ciphertext mismatch:\n \t got:  %s\n \t want: %s", i, toHex(dst), toHex(v.ciphertext))
		}
	}
}

func testIncremental(t *testing.T, iter int, size int) {
	sse2, ssse3, avx, avx2, vx := useSSE2, useSSSE3, useAVX, useAVX2, useVX
	msg, ref, stream := make([]byte, size), make([]byte, size), make([]byte, size)

	for i := 0; i < iter; i++ {
		var key [32]byte
		var nonce [24]byte

		for j := range key {
			key[j] = byte(len(nonce) + i)
		}
		for j := range nonce {
			nonce[j] = byte(i)
		}

		for j := 0; j <= len(msg); j++ {
			useSSE2, useSSSE3, useAVX, useAVX2, useVX = false, false, false, false, false
			XORKeyStream(ref[:j], msg[:j], nonce[:], key[:], 20)

			useSSE2, useSSSE3, useAVX, useAVX2, useVX = sse2, ssse3, avx, avx2, vx
			XORKeyStream(stream[:j], msg[:j], nonce[:], key[:], 20)

			if !bytes.Equal(ref[:j], stream[:j]) {
				t.Fatalf("Iteration %d failed:\n Message length: %d\n\n got:  %s\nwant: %s", i, j, toHex(stream[:j]), toHex(ref[:j]))
			}
		}
		copy(msg, stream)
	}
}

var vectors = []struct {
	key, nonce, plaintext, ciphertext []byte
	rounds                            int
}{
	{
		fromHex("0000000000000000000000000000000000000000000000000000000000000000"),
		fromHex("000000000000000000000000000000000000000000000000"),
		nil,
		fromHex("bcd02a18bf3f01d19292de30a7a8fdaca4b65e50a6002cc72cd6d2f7c91ac3d5728f83e0aad2bfcf9abd2d2db58faedd65015dd83fc09b131e271043019e8e0f789e96" +
			"89e5208d7fd9e1f3c5b5341f48ef18a13e418998addadd97a3693a987f8e82ecd5c1433bfed1af49750c0f1ff29c4174a05b119aa3a9e8333812e0c0fea49e1ee0134a70a9d49c24e0cbd8fc3ba27e97c" +
			"3322ad487f778f8dc6a122fa59cbe33e7"),
		20,
	},
	{
		fromHex("8000000000000000000000000000000000000000000000000000000000000000"),
		fromHex("000000000000000000000000000000000000000000000000"),
		nil,
		fromHex("ccfe8a9e93431bd582f07b3eb0f4a7afc22ef39337ddd84f0d3545b318a315a32b3abb96de0fc6acde48b248fe8a80e6fa72bfcdf9d8d2656b991676476f052d937308" +
			"0e30d8c0e217126a3c64402e1d9404ba9d6b8ce4ad5ac9693f3660638c26ea2cd1b4a8d3348c1e179ead353ee72fee558e9994c51a27195e287d00ec2f8cfef8866d1f98714f40cbe4e18cebabf3cd1fd" +
			"3bb65506e5dce1ad09f438bffe2c96d7f2f0827c8c3f2ca59dbaa393785c6b8da7c69c8a4a63ffd113dcc93de8f52dbcfaed5e4cbcc1dc310b1352868fab7b14d930a9f7a7d47bed0eaf5b151f6dac8bd" +
			"45510698bdc205d70b944ea5450888dd3ec753da9708bf06c0714822dda74f285c361abd0cd1071324c253dc421905edca36e8808bffef091e7dbdecebdad98cf70b7cede72e9c3c4108e5b32ffae0f42" +
			"151a8196939d8e3b8384be1"),
		20,
	},
	{
		fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
		fromHex("000102030405060708090a0b0c0d0e0f1011121314151617"),
		nil,
		fromHex("e53a61cef151e81401067de33adfc02e90ab205361b49b539fda7f0e63b1bc7d68fbee56c9c20c39960e595f3ea76c979804d08cfa728e66cb5f766b840ec61f9ec20f" +
			"7f90d28dae334426cecb52a8e84b4728a5fdd61deb7f1a3fb63dadf5595e06b6e441670964d595ae59cf21536271bae2594774fb19079b933d8fe744f4"),
		20,
	},
}
