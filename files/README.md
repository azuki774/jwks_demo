## files

### 秘密鍵

```
openssl genpkey -algorithm ed25519 -out ed25519.pem
```

#### 公開鍵

```
openssl pkey -in ed25519.pem -pubout -out ed25519_pub.pem
```

