# sha512
-----------
* Functional Interface
```
use sha512::sha512;
let msg: &[u8] = b"Hello, world!".as_slice();
let digest: [u8; 64] = sha512(msg);
...
```

* Or the Hasher style
```
use sha512::Sha512;
let msg: &[u8] = b"Rest of the message".as_slice();
let digest: [u8; 64] = Sha512::new()
                        .write_u8(1)
                        .write_u32(2)
                        .write(msg)
                        .finish();
...
```