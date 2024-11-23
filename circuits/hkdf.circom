pragma circom 2.1.8;

include "./hmac/circuits/hmac.circom";

// ss : secret length
// is : info length
// k : key length
// m : number of keys to extract
// n : key length
template HKDFSha256(s,i,k,m,n){
  signal input secret[s];
  signal input info[i];
  signal input key[k];

  component hmac = HmacSha256(s, k);
  signal output out[m][n];

  hmac.message <== secret;
  hmac.key <== key;

  component extract = Extract(i, 32, m, n);
  extract.info <== info;
  extract.key <== hmac.hmac;

  out <== extract.out;
}

// n : message length
// k : key length
// out : 32 bytes from sha256 hmac
template Expand(n,k){
  signal input secret[n];
  signal input key[k];

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
  signal input info[n];
  signal input key[k];
  
  var size = 32 + n + 1; // 32 bytes for hmac, n bytes for info, 1 byte for counter

  // hash size is 32 bytes 
  var rounds = (m*s)\(32);
  rounds = (rounds * 32) < (m*s) ? rounds + 1 : rounds;


  component hmac[rounds];

  signal expandedKeys [rounds][32];
  signal output out[m][s];

  hmac[0] = HmacSha256(1, k);
  hmac[0].message[0] <== 1; // here counter is byte(1)
  hmac[0].key <== key;
  expandedKeys[0] <== hmac[0].hmac;
  
  var counter = 2; // counter is byte(2)

  for(var i = 1; i < rounds; i++){
    hmac[i] = HmacSha256(size, k);
    for (var j = 0; j < 32; j++){
      hmac[i].message[j] <== expandedKeys[i-1][j];
    }
    for (var j = 0; j < n; j++){
      hmac[i].message[32+j] <== info[j];
    }
    hmac[i].message[32+n] <== counter;
    hmac[i].key <== key;
    expandedKeys[i] <== hmac[i].hmac;
    counter = counter + 1;
  }

  var byteIndex = 0;
  for (var i = 0; i < m; i++) {
    for (var j = 0; j < s; j++) {
      out[i][j] <== expandedKeys[byteIndex \ 32][byteIndex % 32];
      byteIndex++;
    }
  }
}


