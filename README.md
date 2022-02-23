Generate private key

```
openssl genrsa -out private.key 2048
```

Extract the public key

```
openssl rsa -in private.key -pubout > public.key
```