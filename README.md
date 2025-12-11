## Privacy Cash SDK
This is the SDK for Privacy Cash. It has been audited by Zigtur (https://x.com/zigtur).

### Disclaimer
This SDK powers Privacy Cash's frontend, assuming the single wallet use case. If you use it or published npm library from this repo, please fully test and beware of the inherent software risks or potential bugs.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

### Usage
This SDK provides APIs for developers to interact with Privacy Cash relayers easily. Developers can easily deposit/withdraw/query balances in Privacy Cash solana program.

Main APIs for this SDK are:
a. for SOL:
deposit(), withdraw(), getPrivateBalance()
b. for USDC:
depositUSDC(), withdrawUSDC(), getPrivateBalanceUSDC()

Check the example project under /example folder. The code should be fairly self-explanatory.

Use node version 24 or above.

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