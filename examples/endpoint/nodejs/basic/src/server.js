/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import express from "express";
import { decryptRequest, encryptResponse, FlowEndpointException } from "./encryption.js";
import { getNextScreen } from "./flow.js";
import crypto from "crypto";
import {a} from "./keyGenerator.js"

const app = express();

app.use(
  express.json({
    // store the raw request body to use it for signature verification
    verify: (req, res, buf, encoding) => {
      req.rawBody = buf?.toString(encoding || "utf8");
    },
  }),
);

const { APP_SECRET, PASSPHRASE = "test", PORT = "3001" } = process.env;

const PRIVATE_KEY = `-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,F48AC99D1DE60719

TDEM4yTBHkgalm5gWBsw3DkH9gh3Oddk4yqtIXDPIoksak1vh6eoir7/7PQNmn7K
5f/+G0dGnKS4fWVDI/Rm9bR4T50I2kXa0DSzQpxKftifSlSvhqI0EEZV5uvTZpKg
Offw1tJrtuzA/d/OYN7HfmF4ooc3qUjolSvn0FGza6EM3bzgUiid+50u6Sog+4HS
jOZYieHz/2yy/lol1TRka0uxS736T/7hk7O2Mri1Qel8pjMgijqA1K5KcFPqo53t
kFny9lSPz/bdOlZ95V95OPplpnDR23DeyGvJPcjEpcoI0nIsfOWIPFFKiIhZL8cD
wdnKHIv9laZoX4k3KRg7KcQJmuo4ClbEryiXX924U1c2ftFJxUpojXRnmYXke5ga
vcaYW9l96V36zLxHtMis5I62l9R1HNUK6NnidetaxJeHR9hZ2OBTd2IqVRpO2ALL
BzVPbE0paPKa8Px9Kl9mhAPFZIygZkl9XA+edAAlX7l3odIi/3NEpv83IT2H/Qkj
GY0t0jSul3OiMDakH4D0ylZO6AbBYFzpDhz+KM4u0jibCpZeJVj+sTsP3uzDkuXn
Wpo6s2C9bzuRraDLSSNoSTRaeNfxgjo6u0Fi94wwcCGwlUpr66uFv09kM6dZ6QUK
xM/va7wHqGZ3ZzpRriARv0Qt2LldfE9vD9lyDa0ts4+JNSqZx/fL2cjfm++HWEk+
5tsJF6l89NhjBIjasY12V0qfMnKcHn7KFTIMvMcv1cMWFxCiURJAXkbW3t7AWBjH
dOlERmBeUeTAQfuDoTDAKXfd2NNjvxv5DyaJkqLs+6PD4ctD+BBz/XCsQ5q2Ive9
jLerGKIpElKNljXNElSH6FdWaDjc+qfESVQwE9vJe9iL4R1UHwgSob3WFLSXeOSZ
AgNEBYwhbTeDrF/mI4uuPhO7PeK4D+QrdhsR3hgE28RFdueMt2ARvs6abBO7RW3O
T6OjpDnm0TD1ctOAeXAnM0+MtHfoIMn3K1DafBYO42GnIgCk5BpaygNoeJ8o1OwV
IYJW3GYJ1Z26YhC1S/ja0vsRR6P+5YFau3orzRDX6ASKknyEQW6T22Zw6hX2rSzi
waK5iAe6e3tFk7/iwNULQLAEr3PqE51pqRYkn/zc36XX6qmzJ940mYPTQdmDEAJN
sdOGpmCxHXCQZ+UImMzmt5GlDN5qR9LCVFyThWo4pYOSzNZ86hOvTF/xOTROFg1+
cvwg4eFeb1rsITsXJsfT9b0GSg7jHdHTcNvQKgqTUBAIzk/TEWXdB40D/XYOi+On
BH8nJq7BP4C87Z0mkeskrtbIe+OB7Z9cGIuhOzkUv7NRdgevbdeemI5m1ZNLdJSc
9d/zgvEp7DuBAbnU8+qBE44ShGTnVPynTLsXPgMkrF143jU1JCAIhWGpTDS8OJcv
43qTlQLOaCzp5h7PujkjJYLUeiuiPsmh0gL9R6dfcc0fJSpGBnfNUm81eM0g01nY
sxI8MGnFd1uGhkDYjrF18oJvxpjQXq6lMlXxG5scYrldMPKqHvGlPteshY9vg6eH
2nY8Zik8buOdRj+g2N2UPjcvrWLMlryMPWmx7Cs5Vx+RxbW9vFg47EL22tQmygw9
-----END RSA PRIVATE KEY-----
`

/*
Example:
```-----[REPLACE THIS] BEGIN RSA PRIVATE KEY-----
MIIE...
...
...AQAB
-----[REPLACE THIS] END RSA PRIVATE KEY-----```
*/

app.post("/", async (req, res) => {
  if (!PRIVATE_KEY) {
    throw new Error(
      'Private key is empty. Please check your env variable "PRIVATE_KEY".'
    );
  }

  // if(!isRequestSignatureValid(req)) {
  //   // Return status code 432 if request signature does not match.
  //   // To learn more about return error codes visit: https://developers.facebook.com/docs/whatsapp/flows/reference/error-codes#endpoint_error_codes
  //   return res.status(432).send();
  // }

  let decryptedRequest = null;
  try {
    decryptedRequest = decryptRequest(req.body, PRIVATE_KEY, PASSPHRASE);
  } catch (err) {
    console.error(err);
    if (err instanceof FlowEndpointException) {
      return res.status(421).send();
    }
    return res.status(500).send();
  }

  const { aesKeyBuffer, initialVectorBuffer, decryptedBody } = decryptedRequest;
  console.log("💬 Decrypted Request:", decryptedBody);

  // TODO: Uncomment this block and add your flow token validation logic.
  // If the flow token becomes invalid, return HTTP code 427 to disable the flow and show the message in `error_msg` to the user
  // Refer to the docs for details https://developers.facebook.com/docs/whatsapp/flows/reference/error-codes#endpoint_error_codes

  /*
  if (!isValidFlowToken(decryptedBody.flow_token)) {
    const error_response = {
      error_msg: `The message is no longer available`,
    };
    return res
      .status(427)
      .send(
        encryptResponse(error_response, aesKeyBuffer, initialVectorBuffer)
      );
  }
  */

  const screenResponse = await getNextScreen(decryptedBody);
  console.log("👉 Response to Encrypt:", screenResponse);

  res.send(encryptResponse(screenResponse, aesKeyBuffer, initialVectorBuffer));
});

app.get("/", (req, res) => {
  res.send(`<pre>Nothing to see here.
Checkout README.md to start.</pre>`);
});

app.get("/createKey", (req, res) => {

 const decryptedRequest = a();
  res.send(decryptedRequest);
});

app.listen(PORT, () => {
  console.log(`Server is listening on port: ${PORT}`);
});

function isRequestSignatureValid(req) {
  if(!APP_SECRET) {
    console.warn("App Secret is not set up. Please Add your app secret in /.env file to check for request validation");
    return true;
  }

  const signatureHeader = req.get("x-hub-signature-256");
  const signatureBuffer = Buffer.from(signatureHeader.replace("sha256=", ""), "utf-8");

  const hmac = crypto.createHmac("sha256", APP_SECRET);
  const digestString = hmac.update(req.rawBody).digest('hex');
  const digestBuffer = Buffer.from(digestString, "utf-8");

  if ( !crypto.timingSafeEqual(digestBuffer, signatureBuffer)) {
    console.error("Error: Request Signature did not match");
    return false;
  }
  return true;
}
