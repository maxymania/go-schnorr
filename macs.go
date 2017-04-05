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

import "hash"
import "crypto/hmac"

type pureMAC struct{
	h func() hash.Hash
	est int
}
func (p pureMAC) New(key []byte) hash.Hash {
	h := p.h()
	h.Write(key)
	return h
}
func (p pureMAC) MaxHashSize() int { return p.est }

// Implements HASH( key || message )
// est should be h().Size()
func SimpleHash(h func() hash.Hash, est int) KeyMAC{
	return pureMAC{h,est}
}

type hashMAC struct{
	h func() hash.Hash
	est int
}
func (p hashMAC) New(key []byte) hash.Hash {
	h := hmac.New(p.h,key)
	return h
}
func (p hashMAC) MaxHashSize() int { return p.est }

// Implements Keyed-Hash Message Authentication Code (HMAC)
// est should be h().Size()
func HMAC(h func() hash.Hash, est int) KeyMAC{
	return hashMAC{h,est}
}

type anyMAC struct{
	h func(key []byte) hash.Hash
	est int
}
func (p anyMAC) New(key []byte) hash.Hash {
	h := p.h(key)
	return h
}
func (p anyMAC) MaxHashSize() int { return p.est }

func WrapMAC(h func(key []byte) hash.Hash, est int) KeyMAC{
	return anyMAC{h,est}
}
