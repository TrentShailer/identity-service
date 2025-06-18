## Generating Keys

```
openssl ecparam -genkey -noout -name prime256v1 \
    | openssl pkcs8 -topk8 -nocrypt -out ec-private.pem
openssl ec -in ec-private.pem -pubout -out ec-public.pem
```

## Making Requests

```
xh POST http://localhost:8081 --json username=test
```
