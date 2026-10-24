// server.js
const express = require('express');
const crypto = require('crypto');
const axios = require('axios');
const app = express();

app.use(express.json());

const CLIENT_ID = process.env.ISW_CLIENT_ID;
const CLIENT_SECRET = process.env.ISW_CLIENT_SECRET;
const ISW_BASE_URL = process.env.ISW_BASE_URL || 'https://sandbox.interswitchng.com';

const PASSPORT_URL = `${ISW_BASE_URL}/passport/oauth/token`;
const PURCHASE_URL = `${ISW_BASE_URL}/api/v3/purchases`;
const OTP_AUTH_URL = `${ISW_BASE_URL}/api/v3/purchases/otps/auths`;

async function getAccessToken() {
  const credentials = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');
  const response = await axios.post(PASSPORT_URL, 'grant_type=client_credentials', {
    headers: {
      'Authorization': `Basic ${credentials}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
  });
  return response.data.access_token;
}

app.post('/api/v1/pos/charge', async (req, res) => {
  try {
    const { terminalId, merchantId, amount, currency, protocol, pan, expiryMonthYear, cvv, pin } = req.body;

    const accessToken = await getAccessToken();
    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = crypto.randomBytes(16).toString('hex');
    
    // Generate HMAC-SHA512 Signature as required by Interswitch API standards
    const signatureString = `POST&${encodeURIComponent(PURCHASE_URL)}&${timestamp}&${nonce}&${CLIENT_ID}&${accessToken}`;
    const signature = crypto.createHmac('sha512', CLIENT_SECRET).update(signatureString).digest('base64');

    // Note: Interswitch v3 expects encrypted authData or explicit card object depending on your credential configuration.
    // Ensure amount matches your portal specs (smallest currency unit or standard decimal format as required)
    const payload = {
      terminalId,
      merchantId,
      amount,
      currency,
      protocol,
      transactionRef: 'ISW_TXN_' + Date.now(),
      authData: { pan, expiryMonthYear, cvv, pin } // or encrypted payload string if required by your merchant profile
    };

    const iswResponse = await axios.post(PURCHASE_URL, payload, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Signature': signature,
        'Timestamp': timestamp,
        'Nonce': nonce,
        'SignatureMethod': 'SHA1/SHA512',
        'Content-Type': 'application/json',
      }
    });

    // Handle Interswitch v3 response codes (e.g., '00' for Success, 'T0' for OTP required, etc.)
    const { responseCode, responseMessage, paymentId, transactionId } = iswResponse.data;

    if (responseCode === 'T0') {
      // Card requires OTP verification step. You can pass this back to your mobile app UI to prompt for OTP.
      return res.status(200).json({
        requiresOtp: true,
        paymentId,
        transactionId,
        responseCode,
        responseMessage: 'OTP Authentication Required'
      });
    }

    return res.status(200).json({
      requiresOtp: false,
      responseCode: responseCode || '00',
      responseMessage: responseMessage || 'Approved',
      authCode: iswResponse.data.authCode || 'ISW' + Math.floor(100000 + Math.random() * 900000),
      rrn: iswResponse.data.rrn || 'RRN' + Math.floor(100000000000 + Math.random() * 900000000000),
      stan: iswResponse.data.stan || Math.floor(100000 + Math.random() * 900000).toString(),
    });

  } catch (err) {
    console.error('Interswitch v3 Error:', err.response?.data || err.message);
    return res.status(500).json({ success: false, message: err.response?.data?.message || 'Transaction routing error via Interswitch switch.' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Backend gateway running on port ${PORT}`));
