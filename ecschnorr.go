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

import "crypto/elliptic"
import "io"
import crand "crypto/rand"
import "math/big"
//import "hash"

type ECPublicKey struct{
	elliptic.Curve
	X,Y *big.Int
}

type ECPrivateKey struct{
	ECPublicKey
	Key *big.Int
}

func ECGenerateKeyPair(curve elliptic.Curve, rand io.Reader) (pk *ECPrivateKey,e error) {
	pk = new(ECPrivateKey)
	pk.Curve = curve
	cpar := curve.Params()
	pk.Key,e = crand.Int(rand, cpar.N)
	if e!=nil { return }
	pk.X,pk.Y = curve.ScalarBaseMult(pk.Key.Bytes())
	return
}
func ECSign(rand io.Reader, pk *ECPrivateKey, mac KeyMAC) (Signer,error){
	hs := mac.MaxHashSize()
	/* set t1 = pk.Key * (1<<(mac.MaxHashSize()*8)) */
	t2 := new(big.Int).SetUint64(1)
	t1 := new(big.Int).Lsh(pk.Key,uint(mac.MaxHashSize()*8))
	
	k1,e := crand.Int(rand, t1)
	if e!=nil { return nil,e }
	k := new(big.Int).Add(k1,t1)
	k = t2.Add(k,t1)
	rx,ry := pk.Curve.ScalarBaseMult(k.Bytes())
	rb := append(rx.Bytes(),ry.Bytes()...)//elliptic.Marshal(pk.Curve,rx,ry)
	
	
	ha := mac.New(rb)
	return &schnorrSigner{ha,ha,pk.Key,k,hs},nil
}

func ECVerify(pk *ECPublicKey, mac KeyMAC, s *big.Int, e []byte) Verifier {
	
	gsx,gsy := pk.Curve.ScalarBaseMult(s.Bytes())
	yex,yey := pk.Curve.ScalarMult(pk.X,pk.Y,e)
	rx,ry := pk.Curve.Add(gsx,gsy,yex,yey)
	rb := append(rx.Bytes(),ry.Bytes()...)
	
	ha := mac.New(rb)
	return &hashVerifier{ha,ha,e}
}
