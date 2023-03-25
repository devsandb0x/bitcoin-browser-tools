//The MIT License (MIT)
//Copyright (c) 2011-2018 bitcoinjs-lib contributors


async function hmacSHA512(key, data){
  let algorithm = { name: "HMAC", hash: "SHA-512" };
  let keyImp = await crypto.subtle.importKey("raw", key, algorithm, false, ["sign", "verify"]);
  return await crypto.subtle.sign(algorithm.name, keyImp, data);
}

function toBytesInt32 (num) {
  let arr = new ArrayBuffer(4);
  (new DataView(arr)).setUint32(0, num, false);
  return new Uint8Array(arr);
}

const HIGHEST_BIT = 0x80000000;

class BIP32 {

  constructor({version, privateKey, publicKey, chainCode, depth, index, parentFingerprint} = {}){
    Object.assign(this, {version, privateKey, _publicKey:publicKey, chainCode, depth, index, parentFingerprint})
  }

  async init(base58prv){

    let raw = base58.decode(base58prv)
    let key = raw.slice(0, -4)
    let crc = raw.slice(-4)

    let newCrc = await
    crypto.subtle.digest('SHA-256', key.buffer)
      .then(r => crypto.subtle.digest('SHA-256', r)).then(r => new Uint8Array(r).slice(0, 4))

    if(crc.join(",") != newCrc.join(",")) throw new TypeError('Invalid checksum');

    if (key.length !== 78) throw new TypeError('Invalid buffer length');

    this.version = key.slice(0,4) //public: 0x0488b21e, private: 0x0488ade4,
    this.depth = key[4]
    this.parentFingerprint = key.slice(5,9)
    this.index = key.slice(9,13)

    //if (depth === 0 && parentFingerprint !== 0x00000000) throw new TypeError('Invalid parent fingerprint');
    //if (depth === 0 && index !== 0) throw new TypeError('Invalid index');

    this.chainCode = key.slice(13, 45);

    if (new DataView(this.version.buffer).getUint32() == 0x0488ade4){//version === network.this.private) { todo
      if (key[45] !== 0) throw new TypeError('Invalid private key');
      this.privateKey = key.slice(46, 78);
      //hd = fromPrivateKeyLocal(k, chainCode, network, depth, index, parentFingerprint);
      // 33 bytes: public key data (0x02 + X or 0x03 + X)
      //console.log([...tinySecp256k1.pointFromScalar(k)].map(b=>b.toString(16).padStart(2, '0')).join(""))
      //console.log('yoo', tinySecp256k1.isPrivate(k))
    }
    else {
      throw new TypeError('no xpub support yet');
      //public todo neutred not implemented
      this._publicKey = key.slice(45, 78);
      //hd = fromPublicKeyLocal(X, chainCode, network, depth, index, parentFingerprint);
    }


  }

  get publicKey() {
    if (!this._publicKey)
      this._publicKey = tinySecp256k1.pointFromScalar(this.privateKey);
    return this._publicKey;
  }

  get identifier() {
    //todo ripemd160 now implemented
    return crypto.hash160(this.publicKey);
  }
  get fingerprint() {
    return new Uint8Array(4); //todo ripemd160 now implemented
    //return this.identifier.slice(0, 4);
  }

  isNeutered(){
    return !this.privateKey
  }

  async derive(index){

    //derive 0
    let data = new Uint8Array(37)
    const isHardened = index >= HIGHEST_BIT

    if (isHardened) {
      data[0] = 0x00;
      this.privateKey.forEach((i,idx)=>(data[idx+1] = i))
    } else {
      // data = serP(point(kpar)) || ser32(index)
      //      = serP(Kpar) || ser32(index)
      this.publicKey.forEach((i,idx)=>(data[idx] = i))
    }

    toBytesInt32(index).forEach((i, idx)=>data[33+idx] = i);

    const I = new Uint8Array(await hmacSHA512(this.chainCode, data));
    const IL = I.slice(0, 32);
    const IR = I.slice(32);

    // console.log({
    //   index,
    //   I:[...I].map(b=>b.toString(16).padStart(2, '0')).join(" "),
    //   chainCode:[...chainCode].map(b=>b.toString(16).padStart(2, '0')).join(" "),
    //   data1:[...data].map(b=>b.toString(16).padStart(2, '0')).join(" ")
    // })

    // if parse256(IL) >= n, proceed with the next value for i
    if (!tinySecp256k1.isPrivate(IL)) {
      console.log('unrecabhble', index)
      return this.derive(index + 1);
    }
    // Private parent key -> private child key
    if (!this.isNeutered()) {
      // ki = parse256(IL) + kpar (mod n)
      let ki = tinySecp256k1.privateAdd(this.privateKey, IL);
      // In case ki == 0, proceed with the next value for i
      if (ki == null) {
        console.log('unrecabhble', index)
        return this.derive(index + 1);
      }

      return new BIP32({
        version:this.version,
        privateKey: ki,
        chainCode: IR,
        depth: this.depth+1,
        index:toBytesInt32(index),
        parentFingerprint:this.fingerprint
      })


    } else {
      //todo neutred not implemented
      // // Public parent key -> public child key
      //
      // // Ki = point(parse256(IL)) + Kpar
      // //    = G*IL + Kpar
      // const Ki = Buffer.from(ecc.pointAddScalar(this.publicKey, IL, true));
      // // In case Ki is the point at infinity, proceed with the next value for i
      // if (Ki === null)
      //   return this.derive(index + 1);
      // hd = fromPublicKeyLocal(Ki, IR, this.network, this.depth + 1, index, this.fingerprint.readUInt32BE(0));
    }

  }

  deriveHardened(index){
    return this.derive(index + HIGHEST_BIT)
  }

  async derivePath(path) {
    let splitPath = path.split('/');
    if (splitPath[0] === 'm') {
      //if (this.parentFingerprint) throw new TypeError('Expected master, got child');
      splitPath = splitPath.slice(1);
    }

    let target = this

    for(let indexStr of splitPath){
      let index;
      if (indexStr.slice(-1) === `'`) {
        index = parseInt(indexStr.slice(0, -1), 10);
        target = await target.deriveHardened(index);
      } else {
        index = parseInt(indexStr, 10);
        target =  await target.derive(index);
      }
    }
    return target
  }

}
