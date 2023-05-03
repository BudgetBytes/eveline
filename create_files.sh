#!/bin/bash
for n in {1..20}; do
    cp ./backup/image.png ./test/image$(printf "%03d" "$n").png 
    cp ./backup/PDF_1MB.pdf ./test/PDF_1MB$(printf "%03d" "$n").pdf
    cp ./backup/video.mp4 ./test/video$(printf "%03d" "$n").mp4 
done
#time dd if=/dev/urandom of=file_large1.bin bs=1M count=1024
#time dd if=/dev/urandom of=file_large2.bin bs=1M count=1024
#time dd if=/dev/urandom of=file_large3.bin bs=1M count=1024
