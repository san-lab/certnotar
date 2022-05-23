package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/kubasiemion/ibmdilithium/ibmdilithium"
	"github.com/kubasiemion/x509PQexpansion/x509"
	kmsclitool "github.com/proveniencenft/kmsclitool/common"
)

var ethaddr = "746D2391A33011e8515FC9D2C0fA9c7DDd882205" //"b0704A27a633ED43afB168AE7d9C662bCfc1d678"

var ethkey string

func init() {

	kf, e := kmsclitool.ReadKeyfile("test746d2391a33.json")
	if e != nil {
		panic(e)
	}
	key, e := kmsclitool.KeyFromPassScrypt([]byte("kaczuszka"), kf.Crypto.KdfScryptParams)
	if e != nil {
		panic(e)
	}
	pltx, e := kmsclitool.Decrypt(kf, key)
	if e != nil {
		panic(e)
	}
	ethkey = hex.EncodeToString(pltx)

}

func main() {
	block, _ := pem.Decode([]byte(selfSignedRootCertRSA4096Pem))
	RootCert, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		fmt.Println(e)
		return
	}

	//fmt.Println(RootCert.SerialNumber)

	cte := GetTemplate()
	cte.SerialNumber = big.NewInt(420042)
	cte.Issuer.OrganizationalUnit = []string{"Some_Intermediate_Unit"}

	block, _ = pem.Decode([]byte(rsa4096privPem))
	rootRSAKey, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	if e != nil {
		fmt.Println(e)
		return
	}

	block, _ = pem.Decode([]byte(intermediateRSA2048keyPem))
	interRSAKey, e := x509.ParsePKCS1PrivateKey(block.Bytes)
	if e != nil {
		fmt.Println(e)
		return
	}

	interCertBytes, e := x509.CreateCertificate(rand.Reader, cte, RootCert, &interRSAKey.PublicKey, rootRSAKey)
	if e != nil {
		fmt.Println(e)
		return
	}

	interCerts, e := x509.ParseCertificates(interCertBytes)
	if e != nil {
		fmt.Println(e)
		return
	}
	if len(interCerts) == 0 {
		fmt.Println("No certificates found")
		return
	}
	interCert := interCerts[0]

	e = interCert.CheckSignatureFrom(RootCert)
	if e != nil {
		fmt.Println(e)
		return
	}

	//fmt.Println(interCert.SerialNumber)

	pqPubKey := new(x509.PQPublicKey)
	propr := ibmdilithium.TestPubKey()

	pqPubKey.OID = propr.GetOID()
	pqPubKey.RawBytes = propr.Bytes

	ca := GetTemplate()

	p2, txh, e := CreateAndNotarizeCertificate(ca, interCert, pqPubKey, interRSAKey, big.NewInt(11155111), true)
	if e != nil {
		fmt.Println(e)
		return
	}
	fmt.Println("Issued new PQ certificate:")
	fmt.Println(CertString(p2))

	block = &pem.Block{Type: "CERTIFICATE", Bytes: p2.Raw}
	certbuf := new(bytes.Buffer)
	e = pem.Encode(certbuf, block)
	if e != nil {
		fmt.Println(e)
		return
	}

	filename := "tx" + txh
	os.WriteFile(filename, certbuf.Bytes(), 0700)
	rootpool := x509.NewCertPool()
	rootpool.AddCert(RootCert)
	intpool := x509.NewCertPool()
	intpool.AddCert(interCert)
	fmt.Println()
	fmt.Println("==================================")
	fmt.Println("Verifying the chain of trust")

	chains, err := p2.Verify(x509.VerifyOptions{Roots: rootpool, Intermediates: intpool})
	fmt.Println("Chain verification error:", err)
	fmt.Println(PrCertChains(chains))
	//fmt.Println("v:", p2.CheckSignatureFrom(interCert))

}

func CreateAndNotarizeCertificate(template *x509.Certificate, parent *x509.Certificate, pubkey interface{},
	privkey interface{}, chainID *big.Int, locking bool) (*x509.Certificate, string, error) {

	e := Dial(int(chainID.Int64()))
	if e != nil {

		return nil, "", e
	}
	nonce, e := getNonce()
	if e != nil {

		return nil, "", e
	}
	noncebytes := big.NewInt(int64(nonce)).Bytes()
	if len(noncebytes) == 0 {
		noncebytes = []byte{0}
	}
	chainIDbytes := chainID.Bytes()
	data := append(getEthAddr(), byte(len(chainIDbytes)))
	data = append(data, chainIDbytes...)
	data = append(data, noncebytes...)
	template.SerialNumber = new(big.Int).SetBytes(data)

	certb, e := x509.CreateCertificate(rand.Reader, template, parent, pubkey, privkey)
	if e != nil {

		return nil, "", e
	}

	p2, e := x509.ParseCertificate(certb)
	if e != nil {

		return nil, "", e
	}
	txh, e := NotarizeLocking(p2.Signature, nonce)

	return p2, txh, e
}

func getEthAddr() []byte {
	b, err := hex.DecodeString(ethaddr)
	if err != nil {
		fmt.Println(err)
	}
	return b
}

func getEthKey() []byte {
	b, _ := hex.DecodeString(ethkey)
	return b
}

var client *ethclient.Client

func Dial(chainid int) error {
	nets, ok := apibychainid[chainid]
	if !ok {
		return fmt.Errorf("Unknown chain")
	}
	if len(nets) < 2 {
		return fmt.Errorf("Unknown API endpoint for %v", chainid)
	}
	var err error
	apiaddr := nets[1]
	client, err = ethclient.Dial(apiaddr)
	return err

}

func getNonce() (uint64, error) {

	privateKey, err := crypto.HexToECDSA(ethkey)
	if err != nil {
		return 0, err
	}

	addr := crypto.PubkeyToAddress(privateKey.PublicKey)
	nonce, err := client.PendingNonceAt(context.Background(), addr)
	if err != nil {
		return 0, err
	}
	return nonce, nil
}

func getChainID() (*big.Int, error) {
	return client.ChainID(context.Background())
}

func NotarizeLocking(data []byte, nonce uint64) (string, error) {
	txh, err := Notarize(data, nonce)
	if err != nil {
		return "", err
	}
	var pending bool
	for pending || err == ethereum.NotFound {
		_, pending, err = client.TransactionByHash(context.Background(), common.HexToHash(txh))
		time.Sleep(time.Second * 20)
	}
	return txh, err

}

func Notarize(data []byte, nonce uint64) (string, error) {
	//If data too long, hash to 512
	//if len(data) > 64 {
	//	h := sha512.Sum512(data)
	//	data = h[:]
	//}
	chainID, err := client.ChainID(context.Background())
	if err != nil {
		return "", err
	}

	privateKey, err := crypto.HexToECDSA(ethkey)
	if err != nil {
		return "", err
	}
	toAddress := crypto.PubkeyToAddress(privateKey.PublicKey)

	value := big.NewInt(0)
	gasLimit := uint64(210000) // in units
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		return "", err
	}

	//toAddress := common.HexToAddress(ethaddr)

	tx := types.NewTransaction(nonce, toAddress, value, gasLimit, gasPrice, data)

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		return "", err
	}

	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		return "", err
	}

	fmt.Printf("tx sent: %s\n\n", signedTx.Hash().Hex())
	return signedTx.Hash().Hex(), nil
}

/*
func ReadBlockchainTime(cert *Certificate) string {
	serbytes := cert.SerialNumber.Bytes()
	if len(serbytes) < 23 {
		return "Serial number too short for a notarized cert"
	}
	addrbytes := serbytes[:20]
	chainidlen := int(serbytes[20])
	if len(serbytes) - 20 - chainidlen <1 {
		return "Serial number too short for a notarized cert"
	}
	chainid := new(big.Int).SetBytes(serbytes[21:21+chainidlen])
	nonce := new(big.Int).SetBytes(serbytes[21+chainidlen:])
	err := Dial(int(chainid.Int64()))
	if err!= nil {
		return fmt.Sprintf("Error connecting: %s", err)
	}
	client
}
*/

var apibychainid = map[int][]string{ // chainid -> [name, url]
	80001:    {"Polygon Testnet Mumbai", "https://matic-mumbai.chainstacklabs.com"},
	1:        {"Ethereum Mainnet"},
	3:        {"Ethereum Testnet Ropsten", "https://ropsten.infura.io/v3/9580584257984a17927f94f2dd44aa46"},
	4:        {"Ethereum Testnet Rinkeby"},
	5:        {"Ethereum Testnet Goerli", "https://goerli.infura.io/v3/9580584257984a17927f94f2dd44aa46"},
	11155111: {"Ethereum Sepolia", "https://nunki.htznr.fault.dev/rpc"},

	42: {"Ethereum Testnet Kovan"},
}

/*
Chain ID
Network

56
Binance Smart Chain Mainnet
97
Binance Smart Chain Testnet
137
Polygon (previously Matic) Mainnet

30
RSK Mainnet
31
RSK Testnet
16
Flare Testnet Coston
19
Songbird Mainnet
128
HECO Chain Mainnet
100
Gnosis Chain (prev. xDai Chain) Mainnet
250
Fantom Mainnet Opera
50
XinFin Network Mainnet
42220
Celo Mainnet
321
KCC Mainnet
43114
Avalanche C-Chain Mainnet
42161
Arbitrum
421611
Arbitrum Testnet Rinkeby
288
BOBA L2
66
OEC
10
Metadium Mainnet
12
Metadium Testnet
246
EWC (Energy Web Token) Mainnet
1666600000
Harmony Mainnet
1666700000
Harmony Testnet
2017
Orbit Chain Mainnet
*/
