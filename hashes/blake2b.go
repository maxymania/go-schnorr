/*
MIT License

Copyright (c) 2017 Simon Schmidt

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/


package hashes

import "golang.org/x/crypto/blake2b"
import "github.com/maxymania/go-schnorr"
import "hash"

type h_blake2b struct{}
func (o h_blake2b) MaxHashSize() int { return 64 }
func (o h_blake2b) New(key []byte) hash.Hash {
	if len(key)>64 { x := blake2b.Sum512(key); key = x[:] }
	h,_ := blake2b.New512(key)
	return h
}

// Implements the keyed BLAKE2b-512 MAC. If the key is > 64, then the key
// is BLAKE2b-512-Hashed first.
func NewBlake2b() schnorr.KeyMAC {
	return h_blake2b{}
}

