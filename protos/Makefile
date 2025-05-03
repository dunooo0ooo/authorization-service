CURDIR=$(shell pwd)
GENERATEDDIR=${CURDIR}/gen/
PROTODIR=${GENERATEDDIR}/go

proto-generate:
	rm -rf ${PROTODIR}
	mkdir -p ${PROTODIR}
	protoc --proto_path=${CURDIR}/proto/auth \
	--go_out ${PROTODIR} \
	--go-grpc_out ${PROTODIR} \
	${CURDIR}/proto/auth/auth.proto
	go mod tidy