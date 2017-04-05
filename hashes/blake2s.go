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

import "golang.org/x/crypto/blake2s"
import "github.com/maxymania/go-schnorr"
import "hash"

type h_blake2s struct{}
func (o h_blake2s) MaxHashSize() int { return 64 }
func (o h_blake2s) New(key []byte) hash.Hash {
	if len(key)>32 { x := blake2s.Sum256(key); key = x[:] }
	h,_ := blake2s.New256(key)
	return h
}

// Implements the keyed BLAKE2s-256 MAC. If the key is > 32, then the key
// is BLAKE2s-256-Hashed first.
func NewBlake2s() schnorr.KeyMAC {
	return h_blake2b{}
}

