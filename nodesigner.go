package main

import (
	// "encoding/hex"
	"encoding/base64"
	"fmt"

	// "google.golang.org/grpc"
//	"google.golang.org/grpc/credentials"

//	remote "github.com/lightningnetwork/lnd/remotesigner"

	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/roasbeef/btcd/btcec"
	"github.com/roasbeef/btcutil"
	"github.com/roasbeef/btcd/chaincfg"
	"github.com/roasbeef/btcd/chaincfg/chainhash"

	"github.com/tv42/zbase32"
)

// nodeSigner is an implementation of the MessageSigner interface backed by the
// identity private key of running lnd node.
type nodeSigner struct {
	privKey *btcec.PrivateKey
}

// newNodeSigner creates a new instance of the nodeSigner backed by the target
// private key.
func newNodeSigner(key *btcec.PrivateKey) *nodeSigner {
	priv := &btcec.PrivateKey{}
	priv.Curve = btcec.S256()
	priv.PublicKey.X = key.X
	priv.PublicKey.Y = key.Y
	priv.D = key.D
	return &nodeSigner{
		privKey: priv,
	}
}

// SignMessage signs a double-sha256 digest of the passed msg under the
// resident node's private key. If the target public key is _not_ the node's
// private key, then an error will be returned.
func (n *nodeSigner) SignMessage(pubKey *btcec.PublicKey,
	msg []byte) (*btcec.Signature, error) {

	fmt.Println("Hi! I was asked to sign")
	fmt.Println("____________ message ___________")
	fmt.Println(msg)

	// Otherwise, we'll sign the dsha256 of the target message.
	digest := chainhash.DoubleHashB(msg)
	fmt.Println("____________ hashed: _______")
	fmt.Println(digest)
	calc_sign, err := n.privKey.Sign(digest)
	if err != nil {
		return nil, fmt.Errorf("can't sign the message: %v", err)
	}

	// If this isn't our identity public key, then we'll exit early with an
	// error as we can't sign with this key.
	if !pubKey.IsEqual(n.privKey.PubKey()) {
		return nil, fmt.Errorf("unknown public key")
	}

	fmt.Println("____________ proper signed: _______")
	fmt.Println(calc_sign)
	fmt.Println("____________")
	fmt.Println(base64.StdEncoding.EncodeToString(calc_sign.Serialize()))
	fmt.Println("____________")

	wif, err := btcutil.NewWIF(n.privKey, &chaincfg.TestNet3Params, false)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	fmt.Println("____________ My private key is __________")
	fmt.Println(wif.String())
	fmt.Println("____________")
	//
	// fmt.Println("____________ My public key from WIF is __________")
	// fmt.Println(wif.SerializePubKey())
	// fmt.Println("____________")
	//
	// fmt.Println("____________ My public key is __________")
	// fmt.Println(n.privKey.PubKey())
	// fmt.Println("____________")

	// data := hex.EncodeToString( msg )
	r := newRemoteSigner()
	sign, err := r.SignMessage( msg )
	if err != nil {
		return nil, fmt.Errorf("can't sign the message: %v", err)
	}

//	return sign, nil

	fmt.Println("___________ remote server returned: ___________")
	fmt.Println(sign)

	sigBytes, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	signature, err := btcec.ParseSignature(sigBytes, btcec.S256())
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	fmt.Println("____________ try to create signature __________")
	fmt.Println(signature)
	fmt.Println("____________ base 64 ________________")
	fmt.Println(base64.StdEncoding.EncodeToString(signature.Serialize()))

	fmt.Println("____________ zbase 32 ________________")
	fmt.Println(zbase32.EncodeToString(signature.Serialize()))

	return signature, nil
}

// SignCompact signs a double-sha256 digest of the msg parameter under the
// resident node's private key. The returned signature is a pubkey-recoverable
// signature.
func (n *nodeSigner) SignCompact(msg []byte) ([]byte, error) {
	r := newRemoteSigner()
	sigBytes, err := r.SignCompact( msg )
	if err != nil {
		return nil, fmt.Errorf("can't sign the message: %v", err)
	}

	fmt.Println("[SIGN COMPACT]: remote server returned:")
	fmt.Println(sigBytes)

	// We'll sign the dsha256 of the target message.
	digest := chainhash.DoubleHashB(msg)

	bytes, err := n.SignDigestCompact(digest)

	fmt.Println("[SIGN COMPACT]: valid bytes")
	fmt.Println(bytes)

	return sigBytes, err
}

// SignDigestCompact signs the provided message digest under the resident
// node's private key. The returned signature is a pubkey-recoverable signature.
func (n *nodeSigner) SignDigestCompact(hash []byte) ([]byte, error) {

	// Should the signature reference a compressed public key or not.
	isCompressedKey := true

	// btcec.SignCompact returns a pubkey-recoverable signature
	sig, err := btcec.SignCompact(btcec.S256(), n.privKey, hash,
		isCompressedKey)
	if err != nil {
		return nil, fmt.Errorf("can't sign the hash: %v", err)
	}

	return sig, nil
}

// A compile time check to ensure that nodeSigner implements the MessageSigner
// interface.
var _ lnwallet.MessageSigner = (*nodeSigner)(nil)
