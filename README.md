## Privacy Cash SDK
### Tests
1. To run unit tests:
```
    npm test
```
2. To run e2e test (on Mainnet), you need to put your private key (PRIVATE_KEY) inside .env file under the project root directory, and then run:
```
    npm run teste2e
```
Running e2e tests will cost some transaction fees on your wallet, so don't put too much SOL into your wallet. Maybe put 0.1 SOL, and the tests might cost 0.02 SOL.