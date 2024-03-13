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
DEK-Info: DES-EDE3-CBC,25899AC53E368F2A

DEyxTBTLSKXWre3TICZ8Aks14VLPEsb9hLaQvw2xCfeEuXTyWPOlMrXm/K/4YYiD
tsdby72NlZ+G1QO2zNM90b453XuvQLFiuRfocygP0sZkLoP8zTOP+fIdz4IAxYR8
xWBSaoqBEUb7MLOc96n9ADczPmF/tzmxa92IRlhrw0ZyxnuQyecG3dcZv4i3OmW/
oo80XjcKr1CReMYomJu1sIrncs3LngUUfLHpBAN5ldx/PpjVFGwdNgr8dV6YXGgt
obAPdt3ALJklKDFquCS5d4czltmrBdeemzavr5Y1vU6ilBtg0oNMeQCOEeQfoV1s
rBraHWNx7naoyjeT2qy6G2LzPJV5FXBdHT6qmxGJYCEARKM6OlsphQ0glwDHSiQz
+8kqIDxE2va+q+ojpooQARMq+wlwK+2nbLCRx2A3mSwd9AYLBm33ayLWRGa3K5rF
6SE+HYTVWSMvg9mwLyvDUderIaYupZ5o9a65Bni3HCRBdk0i1lyiQzUx2ry/TAaZ
4yzEXKmIkAQbGdtKk3NvZcb3LxMexbIcwiFpiKdwoiO6i353RyRBz/0y6+KdIVFo
a85jamMIIT6HYAeq0yXB7xcor1uQcBKz/7eZ8RH1SZBDTeq0NoEMCC/1CE9wn0Bt
WJfzgIE36vSIvm7AAyyTLQfbkk2CcFQGHZb4Mmxh5aniB7JYwFMMAGm9HzZEWIVY
uC0qlhNpQUup3fpt8c5eJNdEHncFnAcVx5ady5vcRRfDR6M1TQOqy0ZvLA5lcACD
6q8INdpJzRGAAum6wPFXRalTC1NPC+b0TQnE37n07G430xNfjoMN+rfWKbABjt3D
qQua9wiqwKqt6P5bPR/reQG4qdxa+40jy96uDApQjGJQ3QMPazJYgY4IqGwZbHPf
dqMVV97Tbpzh3+gWIoDSxreUCjxZDDY6kek1BLaGgzeNAhUl1F7J0nqYFlGADCoA
tgcjWIW146H3IVbGz9Y3YFwP0PHP6ff1s32/fyoRKq5ClEqZf3dR8EgOwfFfcmk2
UTX5XzEN1trIOES+ZxVPBqu/OTI6BXXno2rhkSm2DCjWcsv4yDm+F81zj7HTEhmf
vIg3D6HbmhIEcEI6fDLlkeLknaRMBfzZzGbRx3hRwv3rXpIeVo3vwq3YnJbEFgi4
87QD5wcyFYUMse0tnYIsGqefH7Tl5VJ7BtvUoBtxVrxXireJVEFX1SYWLRDf8nVA
ziLYBCWvbanZHP4qi6Xn7I5aBiZmjLMg+B+BZw53IJN5y/x1vupdvuGnBVaUbxH4
cpdjk4a5J8yXObcS44GXw/JJFl9BXKSTb3yfQJSWlsyyGa4mRIAIo6AqP7tDjS30
LsMkqv5WnZ40Uh6mb1ezLWChH6K1HC2OLKUAsqLHfbmVxp+8CgXH1SqzX99z2i1d
ci9djMK7DKR/+YJA8KPXJg8eD9QCRpY+ACNC6AA4lsoOqNS2j4aAuNQ3SeRjNAr3
0QSUTSZ3WxPy0weXFdV3BD8to0MbElqieRWxAvucRYkU3zSEqrqPPwiukyRVPS/S
0n7EyrMO0g+vURsklKk7NnBl66Iev+eT+qe/07k5jLNH/faPLPXvHQ==
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
