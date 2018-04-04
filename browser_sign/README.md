To create browser\_sign.pb.go interface from protobuf file, run from project dir:

	protoc -I browser_sign/ browser_sign/browser_sign.proto --go_out=plugins=grpc:browser_sign


