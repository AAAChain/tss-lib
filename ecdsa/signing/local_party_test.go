// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	ecommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ipfs/go-log"
	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	"github.com/binance-chain/tss-lib/test"
	"github.com/binance-chain/tss-lib/tss"
)

const (
	testParticipants = test.TestParticipants
	testThreshold    = test.TestThreshold
)

func setUp(level string) {
	if err := log.SetLogLevel("tss-lib", level); err != nil {
		panic(err)
	}
}

func publicKeyBytesToAddress(publicKey []byte) ecommon.Address {
	buf := crypto.Keccak256(publicKey[1:])
	address := buf[12:]
	return ecommon.HexToAddress(hex.EncodeToString(address))
}

func TestBNtoBytesAndReverse(t *testing.T) {
	var helloWorldBytes bytes.Buffer
	for i := 0; i < 1000; i++ {
		_, err := helloWorldBytes.WriteString("hello world!")
		assert.Nil(t, err)
	}
	assert.Equal(t, helloWorldBytes.Bytes(), new(big.Int).SetBytes(helloWorldBytes.Bytes()).Bytes())
}

func TestE2EConcurrent(t *testing.T) {
	setUp("info")
	threshold := testThreshold

	client, err := ethclient.Dial("https://kovan.infura.io/v3/954d5bbb46b047d28f31c369502a3da6")
	if err != nil {
		common.Logger.Fatalf("%+v", err)
	}

	// PHASE: load keygen fixtures
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, len(signPIDs))

	pkX, pkY := keys[0].ECDSAPub.X(), keys[0].ECDSAPub.Y()
	pk := ecdsa.PublicKey{
		Curve: tss.EC(),
		X:     pkX,
		Y:     pkY,
	}

	fromAddress := publicKeyBytesToAddress(elliptic.Marshal(pk, pk.X, pk.Y))
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		common.Logger.Fatalf("%+v", err)
	}

	t.Logf("address: %s", fromAddress.String())

	value := big.NewInt(100000000000000000) // in wei (0.001 eth)
	gasLimit := uint64(21000)               // in units
	gasPrice := big.NewInt(20000000000)

	toAddress := ecommon.HexToAddress("0x3bCc7ca67F368fFc0556b2AE83e28dA2Ed4b841b")
	var txData []byte
	tx := types.NewTransaction(nonce, toAddress, value, gasLimit, gasPrice, txData)

	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		common.Logger.Fatalf("%+v", err)
	}

	signer := types.NewEIP155Signer(chainID)
	h := signer.Hash(tx).Bytes()

	// PHASE: signing
	// use a shuffled selection of the list of parties for this test
	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan common.SignatureData, len(signPIDs))

	updater := test.SharedPartyUpdater

	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(p2pCtx, signPIDs[i], len(signPIDs), threshold)

		P := NewLocalParty(new(big.Int).SetBytes(h), params, keys[i], outCh, endCh).(*LocalParty)
		parties = append(parties, P)
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	var ended int32
signing:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break signing

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, errCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(parties[dest[0].Index], msg, errCh)
			}

		case sign := <-endCh:
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
				t.Logf("Done. Received signature data from %d participants", ended)
				R := parties[0].temp.bigR
				r := parties[0].temp.rx
				fmt.Printf("sign result: R(%s, %s), r=%s\n", R.X().String(), R.Y().String(), r.String())

				modN := common.ModInt(tss.EC().Params().N)

				// BEGIN check s correctness
				sumS := big.NewInt(0)
				for _, p := range parties {
					sumS = modN.Add(sumS, p.temp.si)
				}
				fmt.Printf("S: %s\n", sumS.String())
				// END check s correctness

				// BEGIN ECDSA verify
				ok := ecdsa.Verify(&pk, h, R.X(), sumS)
				assert.True(t, ok, "ecdsa verify must pass")

				ok = ecdsa.Verify(&pk, h, new(big.Int).SetBytes(sign.R), new(big.Int).SetBytes(sign.S))
				assert.True(t, ok, "ecdsa verify must pass")

				t.Logf("ECDSA signing test done. %+v", sign)
				// END ECDSA verify

				var sigRaw []byte
				curve := btcec.S256()
				signature := &btcec.Signature{
					R: new(big.Int).SetBytes(sign.R),
					S: new(big.Int).SetBytes(sign.S),
				}
				for i := 0; i < (curve.H+1)*2; i++ {
					pk1, err := recoverKeyFromSignature(curve, signature, h[:], i, true)
					if err == nil && pk1.X.Cmp(pk.X) == 0 && pk1.Y.Cmp(pk.Y) == 0 {
						common.Logger.Infof("\n\n\n================\nbingo %+v\n================\n\n\n", curve.BitSize)
						result := make([]byte, 1, 2*curve.BitSize+1)
						result[0] = 27 + byte(i)
						// Not sure this needs rounding but safer to do so.
						curvelen := (curve.BitSize + 7) / 8

						// Pad R and S to curvelen if needed.
						bytelen := (signature.R.BitLen() + 7) / 8
						if bytelen < curvelen {
							result = append(result,
								make([]byte, curvelen-bytelen)...)
						}
						result = append(result, signature.R.Bytes()...)

						bytelen = (signature.S.BitLen() + 7) / 8
						if bytelen < curvelen {
							result = append(result,
								make([]byte, curvelen-bytelen)...)
						}
						result = append(result, signature.S.Bytes()...)
						sigRaw = result
					}
				}

				assert.True(t, len(sigRaw) > 0)

				vv := sigRaw[0] - 27
				copy(sigRaw, sigRaw[1:])
				sigRaw[64] = vv

				signedTx, err := tx.WithSignature(signer, sigRaw)
				if err != nil {
					panic(err)
				}

				err = client.SendTransaction(context.Background(), signedTx)
				if err != nil {
					t.Fatal(err)
				}

				t.Logf("tx sent: %s", signedTx.Hash().Hex())

				break signing
			}
		}
	}
}

func decompressPoint(curve *btcec.KoblitzCurve, x *big.Int, ybit bool) (*big.Int, error) {
	// TODO: This will probably only work for secp256k1 due to
	// optimizations.

	// Y = +-sqrt(x^3 + B)
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	x3.Add(x3, curve.Params().B)

	// now calculate sqrt mod p of x2 + B
	// This code used to do a full sqrt based on tonelli/shanks,
	// but this was replaced by the algorithms referenced in
	// https://bitcointalk.org/index.php?topic=162805.msg1712294#msg1712294
	y := new(big.Int).Exp(x3, curve.QPlus1Div4(), curve.Params().P)

	if ybit != isOdd(y) {
		y.Sub(curve.Params().P, y)
	}
	if ybit != isOdd(y) {
		return nil, fmt.Errorf("ybit doesn't match oddness")
	}
	return y, nil
}

func isOdd(a *big.Int) bool {
	return a.Bit(0) == 1
}

func recoverKeyFromSignature(curve *btcec.KoblitzCurve, sig *btcec.Signature, msg []byte,
	iter int, doChecks bool) (*btcec.PublicKey, error) {
	// 1.1 x = (n * i) + r
	Rx := new(big.Int).Mul(curve.Params().N,
		new(big.Int).SetInt64(int64(iter/2)))
	Rx.Add(Rx, sig.R)
	if Rx.Cmp(curve.Params().P) != -1 {
		return nil, errors.New("calculated Rx is larger than curve P")
	}

	// convert 02<Rx> to point R. (step 1.2 and 1.3). If we are on an odd
	// iteration then 1.6 will be done with -R, so we calculate the other
	// term when uncompressing the point.
	Ry, err := decompressPoint(curve, Rx, iter%2 == 1)
	if err != nil {
		return nil, err
	}

	// 1.4 Check n*R is point at infinity
	if doChecks {
		nRx, nRy := curve.ScalarMult(Rx, Ry, curve.Params().N.Bytes())
		if nRx.Sign() != 0 || nRy.Sign() != 0 {
			return nil, errors.New("n*R does not equal the point at infinity")
		}
	}

	// 1.5 calculate e from message using the same algorithm as ecdsa
	// signature calculation.
	e := hashToInt(msg, curve)

	// Step 1.6.1:
	// We calculate the two terms sR and eG separately multiplied by the
	// inverse of r (from the signature). We then add them to calculate
	// Q = r^-1(sR-eG)
	invr := new(big.Int).ModInverse(sig.R, curve.Params().N)

	// first term.
	invrS := new(big.Int).Mul(invr, sig.S)
	invrS.Mod(invrS, curve.Params().N)
	sRx, sRy := curve.ScalarMult(Rx, Ry, invrS.Bytes())

	// second term.
	e.Neg(e)
	e.Mod(e, curve.Params().N)
	e.Mul(e, invr)
	e.Mod(e, curve.Params().N)
	minuseGx, minuseGy := curve.ScalarBaseMult(e.Bytes())

	// TODO: this would be faster if we did a mult and add in one
	// step to prevent the jacobian conversion back and forth.
	Qx, Qy := curve.Add(sRx, sRy, minuseGx, minuseGy)

	return &btcec.PublicKey{
		Curve: curve,
		X:     Qx,
		Y:     Qy,
	}, nil
}

func hashToInt(hash []byte, c elliptic.Curve) *big.Int {
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}
