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


package schnorr

import "io"
import "hash"
import "math/big"

import "crypto/subtle"

// MAC Algorithm, that spawns a keyed hash.Hash instance.
type KeyMAC interface {
	// Creates a new, keyed Hash.
	New(key []byte) hash.Hash
	
	// MaxHashSize returns the maximum number of bytes of the hash
	// that will be used. If Hash.Sum() yields more bytes, they'll
	// be cut off. Ideal is Hash.Sum()==MaxHashSize().
	MaxHashSize() int
}

type Signer interface {
	io.Writer
	
	GetSignature() (*big.Int,[]byte)
}
type Verifier interface {
	io.Writer
	
	Verify() bool
}

type hashVerifier struct {
	io.Writer
	h hash.Hash
	b []byte
}
func (hv *hashVerifier) Verify() bool {
	h := hv.h.Sum(nil)
	if len(h) < len(hv.b) { return false }
	if len(h) > len(hv.b) { h = h[:len(hv.b)] }
	return subtle.ConstantTimeCompare(h,hv.b) == 1
}


