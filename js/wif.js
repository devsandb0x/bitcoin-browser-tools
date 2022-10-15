function toWIF(data, compressed = true, network = 0x80){
  let entropy = [network, ...data]
  if(compressed) entropy.push(0x01)
  
  return crypto.subtle.digest('SHA-256', new Uint8Array(entropy).buffer)
    .then(function(r){ return crypto.subtle.digest('SHA-256', r) })
    .then(function(r){ return Array.from(new Uint8Array(r)).slice(0,4) })
    .then(function(crc){
      return base58.encode(new Uint8Array(entropy.concat(crc)))
    });
}