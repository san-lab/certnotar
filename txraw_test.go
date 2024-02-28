package main

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestRawTx(t *testing.T) {
	//Dial(11155111)

	addr := common.HexToAddress("0x1c0e8FC9DEcC4Ae5C4947156aC87D5538bC124fb")
	nonce := uint64(3) //, err := client.PendingNonceAt(context.Background(), addr)
	//if err != nil {
	//	t.Fatal(err)
	//}
	t.Log(nonce)
	privateKey, err := crypto.HexToECDSA("c522c068090d4e888dadbab9967fd81a79a451aff84dce2040df59ad5a6ce1e8")
	if err != nil {
		t.Fatal(err)
	}
	toAddress := addr //crypto.PubkeyToAddress(privateKey.PublicKey)

	value := big.NewInt(100000000000000000) // in wei (0.1 eth)
	gasLimit := uint64(210000)              // in units
	//gasPrice, err := client.SuggestGasPrice(context.Background())
	gasPrice := big.NewInt(100000000)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(gasPrice)

	//toAddress := common.HexToAddress(ethaddr)

	tx := types.NewTransaction(nonce, toAddress, value, gasLimit, gasPrice, nil)

	signedTx, err := types.SignTx(tx, new(types.FrontierSigner), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(signedTx.RawSignatureValues())
	traw, err := signedTx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Raw tx: %x", traw)
	pre := ` curl RPC_HERE   -X POST   -H "Content-Type: application/json"   --data '{"jsonrpc":"2.0", "method":"eth_sendRawTransaction","params":["`
	post := `"],"id":1}'`
	t.Logf("%s%x%s", pre, traw, post)
}

func TestRandomTxSender(t *testing.T) {
	//Dial(11155111)

	addr := common.HexToAddress("0x1c0e8FC9DEcC4Ae5C4947156aC87D5538bC124fb")
	nonce := uint64(3) //, err := client.PendingNonceAt(context.Background(), addr)
	//if err != nil {
	//	t.Fatal(err)
	//}
	t.Log(nonce)
	privateKey, err := crypto.HexToECDSA("c522c068090d4e888dadbab9967fd81a79a451aff84dce2040df59ad5a6ce1e8")
	if err != nil {
		t.Fatal(err)
	}
	toAddress := addr //crypto.PubkeyToAddress(privateKey.PublicKey)

	value := big.NewInt(100000000000000000) // in wei (0.1 eth)
	gasLimit := uint64(210000)              // in units
	//gasPrice, err := client.SuggestGasPrice(context.Background())
	gasPrice := big.NewInt(100000000)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(gasPrice)

	//toAddress := common.HexToAddress(ethaddr)

	tx := types.NewTransaction(nonce, toAddress, value, gasLimit, gasPrice, nil)

	signer := new(types.FrontierSigner)
	h1 := signer.Hash(tx)
	t.Log("pre:", h1.Hex())
	signedTx, err := types.SignTx(tx, signer, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("post:", signer.Hash(signedTx).Hex())

	v, r, s := signedTx.RawSignatureValues()
	t.Logf("%v\n%x\n%x\n", v, r, s)
	sig, err := crypto.Sign(h1.Bytes(), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	sig[3] = byte(8)

	pubbytes, err := crypto.Ecrecover(h1.Bytes(), sig)
	if err != nil {
		t.Fatal(err)
	}
	pubKey, err := crypto.UnmarshalPubkey(pubbytes[:])
	if err != nil {
		t.Fatal(err)
	}
	recAddress := crypto.PubkeyToAddress(*pubKey)
	t.Logf("Recovered: %s", recAddress.Hex())

	if err != nil {
		t.Fatal(err)
	}
	t.Logf("pub: %x", pubbytes)

	t.Logf("x: %x", privateKey.PublicKey.X.Bytes())

	traw, err := signedTx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	//crypto.Ecrecover(signer.Hash(tx)[:])
	t.Logf("Raw tx: %x", traw)
	pre := ` curl RPC_HERE   -X POST   -H "Content-Type: application/json"   --data '{"jsonrpc":"2.0", "method":"eth_sendRawTransaction","params":["`
	post := `"],"id":1}'`
	t.Logf("%s%x%s", pre, traw, post)
}
