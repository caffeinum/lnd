package main

import (
//	"flag"
	"log"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
//	"google.golang.org/grpc/credentials"

	pb "github.com/lightningnetwork/lnd/browser_sign"
)


var serverAddr = "localhost:50051"

// remoteSigner is an implementation of the MessageSigner interface
// that defers message signing to connected browser
type remoteSigner struct {
}

// newNodeSigner creates a new instance of the nodeSigner backed by the target
// private key.
func newRemoteSigner() *remoteSigner {
        return &remoteSigner{}
}

func (r *remoteSigner) SignMessage(msg []byte) (string, error) {
	conn, err := grpc.Dial(serverAddr, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("fail to dial: %v", err)
	}
	defer conn.Close()

	client := pb.NewBrowserSignClient( conn )

	data := &pb.SignMessageRequest{Msg: msg}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	message, err := client.SignMessage( ctx, data )
	if err != nil {
		log.Fatalf("fail to call: %v", err)
		return "", err
	}

	log.Printf("Message received: %v", message)

	return message.Signature, err
}


