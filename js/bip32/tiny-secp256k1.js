//The MIT License (MIT)
//Copyright (c) 2011-2018 bitcoinjs-lib contributors

var tinySecp256k1 = {
  isPoint: function(p){return secp256k1.publicKeyVerify(p) },
  // isPointCompressed
  isPrivate: function(d){return secp256k1.privateKeyVerify(d)},
  pointAdd: function(pA, pB){return secp256k1.publicKeyCombine([pA, pB])},
  pointAddScalar: function(p, tweak){return secp256k1.publicKeyTweakAdd(p, tweak)},
  // pointCompress
  pointFromScalar: function(d){return secp256k1.publicKeyCreate(d)},
  pointMultiply: function(p, tweak){return secp256k1.publicKeyTweakMul(p, tweak)},
  privateAdd: function(d, tweak){
    return secp256k1.privateKeyTweakAdd(new Uint8Array(d), tweak)
  },
  // privateSub
  sign: function(h, d){return secp256k1.ecdsaSign(h, d)},
  verify: function(h, Q, signature){return secp256k1.ecdsaVerify(signature, h, Q)},
}