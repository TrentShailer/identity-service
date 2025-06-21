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

To get JWK:

- Install [`ex-to-jwk`](https://github.com/TrentShailer/ec-to-jwk)
- `ec-to-jwk path/to/ec-public.pem`

## Making Requests

```
xh POST http://localhost:8081 --json x-ts-api-key:identity-service username=test
xh GET http://localhost:8081 Authorization:"bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6InFSX05NMUh0ZHl0T1BRSkM2NTN2bktFaFREYyJ9.eyJleHAiOjE3NTA0Nzk2MTM1NDIsImlzcyI6ImlkZW50aXR5LXNlcnZpY2UiLCJpYXQiOjE3NTA0NjUyMTM1NDIsIm5iZiI6MTc1MDQ2NTIxMzU0Miwic3ViIjoidHMtaWRlbnRpdHktZTg0Y2EwN2YtMmNkZC00YWRiLTllZGQtYTQxMDcxY2ZhNzJmIn0.5g7n_HAiqMt4j7RNTFGfqdTU1I24EXiVlwwTWAH-biChl063aHMn9wdaZtG0eOsDy9zmRUpjN0cEh_hODrfSxQ" x-ts-api-key:identity-service
xh GET http://localhost:8081/.well-known/jwks.json
```
