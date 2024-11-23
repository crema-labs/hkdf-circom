pragma circom 2.1.5;

include "./hmac/circuits/hmac.circom";
import "circomlib/circuits/comparators.circom";

template HKDFSha256(ss,is,k,m,s){
  signal input info[is];
  signal input secret[ss];
  signal input key[k];

  component hmac = HmacSha256(ss, k);
  signal output out[m][s];

  hmac.message <== secret;
  hmac.key <== key;

  component extract = Extract(is, 32, m, s);
  extract.info <== info;
  extract.key <== hmac.hmac;

  out <== extract.out;
}

// n : message length
// k : key length
// out : 32 bytes from sha256 hmac
template Expand(n,k){
  signal input secret[n];
  signal input key[n];

  component hmac = HmacSha256(n, k);
  signal output out[32];

  hmac.message <== secret;
  hmac.key <== key;

  out <== hmac.hmac;
}

// n : message length
// k : key length
// m : number of keys to extract
// s : key length
template Extract(n,k,m,s){
  signal input info[n]
  signal input key[k]
  signal counter = 1; // counter is byte(1)
  signal size = 32 + n + 1; // 32 bytes for hmac, n bytes for info, 1 byte for counter

  // hash size is 32 bytes 
  signal rounds = (32 * m)\s;
  rounds = (rounds * s) < (32 * m) ? rounds + 1 : rounds;


  component hmac[rounds];

  signal expandedKeys [rounds][32];
  signal output out[m][s];

  hmac[0] = HmacSha256(0, k);
  hmac[0].key <== key;
  expandedKeys[0] <== hmac[0].hmac;

  for(var i = 1; i < rounds; i++){
    hmac[i] = HmacSha256(size, k);
    for (var j = 0; j < n; j++){
      hmac[i].message[j] <== expandedKeys[i-1][j];
    }
    for (var j = 0; j < 32; j++){
      hmac[i].message[n+j] <== info[j];
    }
    hmac[i].message[32+n] <== counter;
    hmac[i].key <== key;
    expandedKeys[i] <== hmac[i].hmac;
    counter <== counter + 1;
  }

  signal xindex = 0;
  signal yindex = 0;
  for(var i = 0; i < m; i++){
    for(var j = 0; j < s; j++){
      out[i][j] <== expandedKeys[xindex][yindex];
      yindex = yindex + 1;
      if(yindex == 32){
        xindex = xindex + 1;
        yindex = 0;
      }
    }
  }
}


