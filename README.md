# Identity Service

API for handling identity and authentication for my web services.

> [!CAUTION]
>
> ### This is a personal project
>
> Maintenance, bug fixes, new features, and support will only be provided when/if I feel like it.
> Updates may violate semantic versioning.

## Generating JWT Keys

```
openssl ecparam -genkey -noout -name prime256v1 \
    | openssl pkcs8 -topk8 -nocrypt -out ec-private.pem
openssl ec -in ec-private.pem -pubout -out ec-public.pem
```

## Making Requests

```
xh POST http://localhost:8081 --json username=test
```
