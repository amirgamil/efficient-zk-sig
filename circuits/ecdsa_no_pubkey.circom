
pragma circom 2.0.6;
include "./secp256k1_scalar_mult_cached_windowed.circom";
include "./circom-ecdsa-circuits/secp256k1.circom";
include "../node_modules/circomlib/circuits/gates.circom";

template ECDSAVerifyNoPubkey(n, k) {
    signal input s[k];
    signal input TPreComputes[32][256][2][4]; // T = r^-1 * R
    signal input U[2][k]; // -(m * r^-1 * G)
    signal output pubKey[2][k];

    signal input msghash[k]; 
    signal input generator[2][k]; // G
    signal input rInv[k]; // r^-1

    // verify U is computed correctly
    // compute r^-1 * G
    component secprG = Secp256k1ScalarMult(n, k); 
    for (var idx = 0; idx < k; idx++) {
        secprG.scalar[idx] <== rInv.[idx];
        secprG.point[0][idx] <== generator[0][idx];
        secprG.point[1][idx] <== generator[1][idx];
    }

    // compute m * r^-1 * G
    component secpmsgRG = Secp256k1ScalarMult(n, k);
    for (var idx = 0; idx < k; idx++) {
        secpmsgRG.scalar[idx] <== msghash.[idx];
        secpmsgRG.point[0][idx] <== secprG.out[0][idx];
        secpmsgRG.point[1][idx] <== generator.out[1][idx];
    }

    signal computedU[2][k];
    
    // compute U = -(m * r^-1 * G)
    component xORNegator[2][k];
    for (var idx = 0; idx < k; idx++) {
        xORNegator[0][idx] = XOR();
        xORNegator[1][idx] = XOR();

        xORNegator[0][idx].a <== secpmsgRG.out[0][idx];
        xORNegator[0][idx].b <== 1;

        xORNegator[1][idx].a <== secpmsgRG.out[1][idx];
        xORNegator[1][idx].b <== 1;

        computedU[0][idx] <== xORNegator[0][idx].out;
        computedU[1][idx] <== xORNegator[1][idx].out;
    }

    for (var i = 0; i < k; i++) {
        U[0][i] === computedU[0][i];
        U[1][i] === computedU[1][i];
    }



    // s * T
    // or, s * r^-1 * R
    component sMultT = Secp256K1ScalarMultCachedWindowed(n, k);
    var stride = 8;
    var num_strides = div_ceil(n * k, stride);

    for (var i = 0; i < num_strides; i++) {
        for (var j = 0; j < 2 ** stride; j++) {
            for (var l = 0; l < k; l++) {
                sMultT.pointPreComputes[i][j][0][l] <== TPreComputes[i][j][0][l];
                sMultT.pointPreComputes[i][j][1][l] <== TPreComputes[i][j][1][l];
            }
        }
    }

      for (var i = 0; i < k; i++) {
        sMultT.scalar[i] <== s[i];
    }

    // s * T + U
    // or, s * r^-1 * R + -(m * r^-1 * G)
    component pointAdder = Secp256k1AddUnequal(n, k);
    for (var i = 0; i < k; i++) {
        pointAdder.a[0][i] <== sMultT.out[0][i];
        pointAdder.a[1][i] <== sMultT.out[1][i];
        pointAdder.b[0][i] <== U[0][i];
        pointAdder.b[1][i] <== U[1][i];
    }

    for (var i = 0; i < k; i++) {
        pubKey[0][i] <== pointAdder.out[0][i];
        pubKey[1][i] <== pointAdder.out[1][i];
    }
}
