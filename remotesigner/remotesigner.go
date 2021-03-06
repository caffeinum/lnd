package remotesigner

import (
//	"flag"
	"encoding/base64"
	"log"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
//	"google.golang.org/grpc/credentials"

	// "github.com/roasbeef/btcd/btcec"

	pb "github.com/lightningnetwork/lnd/browser_sign"
)


var serverAddr = "localhost:50051"

// remoteSigner is an implementation of the MessageSigner interface
// that defers message signing to connected browser
type remoteSigner struct {
}

// newNodeSigner creates a new instance of the nodeSigner backed by the target
// private key.
func NewRemoteSigner() *remoteSigner {
        return &remoteSigner{}
}

func (r *remoteSigner) SignMessage(msg []byte) (string, error) {
	conn, err := grpc.Dial(serverAddr, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("fail to dial: %v", err)
	}
	defer conn.Close()

	client := pb.NewBrowserSignClient( conn )

	data := &pb.SignMessageRequest{Msg: msg, Type: "alice_master"}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	signed_message, err := client.SignMessage( ctx, data )
	if err != nil {
		log.Fatalf("fail to call: %v", err)
		return "", err
	}

	// sigBytes, err := base64.StdEncoding.DecodeString(signed_message.Signature)
	// if err != nil {
	// 	log.Fatalf("cant decode: %v", err)
	// 	return "", err
	// }

	// signature, err := btcec.ParseSignature(sigBytes, btcec.S256())
	// if err != nil {
	// 	log.Fatalf("cant parse signature: %v", err)
	// 	return "", err
	// }
	//
	// log.Printf("CLIENT: %v", base64.StdEncoding.EncodeToString(signature.Serialize()))

	return signed_message.Signature, err
}


// SignCompact signs a double-sha256 digest of the msg parameter under the
// resident node's private key. The returned signature is a pubkey-recoverable
// signature.
func (r *remoteSigner) SignCompact(msg []byte) ([]byte, error) {
	conn, err := grpc.Dial(serverAddr, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("fail to dial: %v", err)
	}
	defer conn.Close()

	client := pb.NewBrowserSignClient( conn )

	data := &pb.SignMessageRequest{Msg: msg}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	signed_message, err := client.SignCompact( ctx, data )
	if err != nil {
		log.Fatalf("fail to call: %v", err)
		return nil, err
	}

	sigBytes, err := base64.StdEncoding.DecodeString(signed_message.Signature)
	if err != nil {
		log.Fatalf("cant decode: %v", err)
		return nil, err
	}
	//
	// signature, err := btcec.ParseSignature(sigBytes, btcec.S256())
	// if err != nil {
	// 	log.Fatalf("cant parse signature: %v", err)
	// 	return nil, err
	// }
	//
	// log.Printf("CLIENT: %v", base64.StdEncoding.EncodeToString(signature.Serialize()))

	return sigBytes, err
}


// SignCompact signs a double-sha256 digest of the msg parameter under the
// resident node's private key. The returned signature is a pubkey-recoverable
// signature.
func (r *remoteSigner) SignHash(hash []byte, keyID string) ([]byte, error) {
	conn, err := grpc.Dial(serverAddr, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("fail to dial: %v", err)
	}
	defer conn.Close()

	client := pb.NewBrowserSignClient( conn )

	var sign_type string
	if ( keyID == "node" ) {
		sign_type = "alice_master"
	} else {
	 	sign_type = "alice"
	}

	data := &pb.SignMessageRequest{Msg: hash, Type: sign_type}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	signed_message, err := client.SignMessage( ctx, data )
	if err != nil {
		log.Fatalf("fail to call: %v", err)
		return nil, err
	}

	sigBytes, err := base64.StdEncoding.DecodeString(signed_message.Signature)
	if err != nil {
		log.Fatalf("cant decode: %v", err)
		return nil, err
	}

	return sigBytes, err
}
