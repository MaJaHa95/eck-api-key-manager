IMG=controller:$VERSION

make docker-build "IMG=$IMG"
kind load docker-image $IMG
make deploy "IMG=$IMG"
