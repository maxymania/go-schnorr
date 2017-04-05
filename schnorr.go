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
import crand "crypto/rand"
import "math/big"
import "hash"

type Group struct{
	P *big.Int
	G *big.Int
}

type PublicKey struct{
	Group
	A *big.Int
}

type PrivateKey struct{
	PublicKey
	Key *big.Int
}

func GenerateKeyPair(group *Group, rand io.Reader) (pk *PrivateKey,e error) {
	pk = new(PrivateKey)
	pk.Group = *group
	pk.Key,e = crand.Int(rand, pk.Group.P)
	if e!=nil { return }
	pk.A = new(big.Int).Exp(pk.Group.G,pk.Key,pk.Group.P)
	return
}

type schnorrSigner struct{
	io.Writer
	h hash.Hash
	priv *big.Int
	k *big.Int
	hs int
}
func Sign(rand io.Reader, pk *PrivateKey, mac KeyMAC) (Signer,error){
	hs := mac.MaxHashSize()
	/* set t1 = pk.Key * (1<<(mac.MaxHashSize()*8)) */
	t2 := new(big.Int).SetUint64(1)
	t1 := new(big.Int).Lsh(pk.Key,uint(mac.MaxHashSize()*8))
	
	k1,e := crand.Int(rand, t1)
	if e!=nil { return nil,e }
	k := new(big.Int).Add(k1,t1)
	k = t2.Add(k,t1)
	r := new(big.Int).Exp(pk.Group.G,k,pk.Group.P)
	ha := mac.New(r.Bytes())
	return &schnorrSigner{ha,ha,pk.Key,k,hs},nil
}
func (s *schnorrSigner) GetSignature() (*big.Int,[]byte){
	sum := s.h.Sum(make([]byte,0,s.h.Size()))
	if len(sum)>s.hs { sum = sum[:s.hs] }
	e := new(big.Int).SetBytes(sum)
	xe := new(big.Int).Mul(e,s.priv)
	sig := e.Sub(s.k,xe)
	return sig,sum
}

func Verify(pk *PublicKey, mac KeyMAC, s *big.Int, e []byte) Verifier {
	E := new(big.Int).SetBytes(e)
	gs := new(big.Int).Exp(pk.Group.G,s,pk.Group.P)
	ye := new(big.Int).Exp(pk.A,E,pk.Group.P)
	rv := new(big.Int).Mul(gs,ye)
	rv = new(big.Int).Mod(rv,pk.Group.P)
	ha := mac.New(rv.Bytes())
	return &hashVerifier{ha,ha,e}
}
