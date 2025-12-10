# Demo Quick Start Guide

## 🚀 Testing the Ed25519 Encrypted Keystore Demo

### Step 1: Install Dependencies

```bash
cd examples/ed25519-encrypted-keystore-demo
npm install
```

### Step 2: Start the Demo

```bash
npm run dev
```

The demo will start on **http://localhost:5173**

### Step 3: Open in Browser

Open **Chrome 106+** or **Edge 106+** for full largeBlob support.

### Step 4: Test the Features

#### A. Basic Test (No Encryption)
1. Click **"Create Credential"** → biometric prompt
2. Uncheck both security options
3. Click **"Authenticate with WebAuthn"**
4. Add some TODOs

**Result**: P-256 DID, unencrypted keystore (old behavior)

#### B. Test Ed25519 DID Only
1. Reset database or reload
2. Create credential if needed
3. ✅ Check **"Use Ed25519 DID from keystore"**
4. ❌ Uncheck **"Encrypt keystore"**
5. Authenticate
6. Check the DID format (should start with `did:key:z6Mk`)

**Result**: Ed25519 DID, but keystore still unencrypted

#### C. Test Full Encryption (Recommended)
1. Reset database or reload
2. Create credential if needed
3. ✅ Check **"Use Ed25519 DID from keystore"**
4. ✅ Check **"Encrypt keystore with WebAuthn"**
5. Select **"largeBlob"** (Chrome/Edge 106+)
6. Authenticate → biometric prompt
7. Add TODOs (no additional prompts!)

**Result**: 
- Ed25519 DID from keystore
- Keystore encrypted with AES-GCM
- Secret key in WebAuthn hardware
- One biometric prompt per session

### Step 5: Verify Encryption

Open Chrome DevTools → Application → Local Storage:
- Look for `encrypted-keystore-*` entries
- You'll see ciphertext (encrypted data)
- Without WebAuthn auth, this data is useless!

### Step 6: Test Session Persistence

1. Reload the page (Cmd+R / Ctrl+R)
2. Click "Authenticate with WebAuthn" → biometric prompt
3. Your TODOs are still there!
4. Same DID across sessions

### What to Look For

#### Console Output
```javascript
🔍 Created WebAuthn identity: {
  id: "did:key:z6Mk...",
  type: "webauthn",
  hash: "...",
  didType: "Ed25519 (from keystore)",
  encrypted: "Yes (largeBlob)"
}
```

#### DID Format
- **P-256**: `did:key:zDna...` (starts with zDna)
- **Ed25519**: `did:key:z6Mk...` (starts with z6Mk)

#### LocalStorage
- **Unencrypted**: Keys in plaintext
- **Encrypted**: Only ciphertext visible

### Browser Support Matrix

| Feature | Chrome 106+ | Edge 106+ | Firefox | Safari |
|---------|-------------|-----------|---------|--------|
| Ed25519 DID | ✅ | ✅ | ✅ | ✅ |
| largeBlob | ✅ | ✅ | ❌ | ❌ |
| hmac-secret | ✅ | ✅ | ✅ | ⚠️ Limited |

### Troubleshooting

#### "No encryption extensions supported"
- You're not on Chrome/Edge 106+
- Try hmac-secret instead
- Or test without encryption first

#### "Failed to create encrypted keystore"
- Check browser console for details
- Try resetting database
- Make sure WebAuthn is working

#### "Database loading failed"
- Click "Reset Database"
- Clear IndexedDB manually
- Restart the dev server

### Testing Checklist

- [ ] Created WebAuthn credential
- [ ] Tested without any options (baseline)
- [ ] Tested Ed25519 DID only
- [ ] Tested encryption with largeBlob
- [ ] Tested encryption with hmac-secret (if supported)
- [ ] Verified DID format (z6Mk for Ed25519)
- [ ] Checked localStorage for encrypted data
- [ ] Tested session persistence (reload page)
- [ ] Added/completed/deleted TODOs
- [ ] Verified only one biometric prompt per session

### Success Criteria

✅ Ed25519 DID starts with `did:key:z6Mk`  
✅ Keystore encrypted in localStorage  
✅ One biometric prompt per session  
✅ TODOs persist across reload  
✅ Console shows encryption status  

## Need Help?

Check the logs in:
1. Browser console (F12)
2. Terminal where `npm run dev` is running
3. Network tab for any API errors

## Clean Up

To reset everything:
```bash
# In browser
Click "Reset Database"

# Or manually
# Chrome: DevTools → Application → Clear Storage → IndexedDB
```

Happy testing! 🎉
