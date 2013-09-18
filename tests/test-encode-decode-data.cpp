/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

#include <cstdlib>
#include <sstream>
#include <iostream>
#include <time.h>
#include "../ndn-cpp/data.hpp"
#include "../ndn-cpp/security/key-chain.hpp"
#include "../ndn-cpp/sha256-with-rsa-signature.hpp"

using namespace std;
using namespace ndn;
using namespace func_lib;
#if HAVE_STD_FUNCTION
// In the std library, the placeholders are in a different namespace than boost.                                                           
using namespace func_lib::placeholders;
#endif

unsigned char Data1[] = {
0x04, 0x82, // NDN Data
  0x02, 0xaa, // Signature
    0x03, 0xb2, // SignatureBits
      0x08, 0x85, 0x20, 0xea, 0xb5, 0xb0, 0x63, 0xda, 0x94, 0xe9, 0x68, 0x7a,
      0x8e, 0x65, 0x60, 0xe0, 0xc6, 0x43, 0x96, 0xd9, 0x69, 0xb4, 0x40, 0x72, 0x52, 0x00, 0x2c, 0x8e, 0x2a, 0xf5,
      0x47, 0x12, 0x59, 0x93, 0xda, 0xed, 0x82, 0xd0, 0xf8, 0xe6, 0x65, 0x09, 0x87, 0x84, 0x54, 0xc7, 0xce, 0x9a,
      0x93, 0x0d, 0x47, 0xf1, 0xf9, 0x3b, 0x98, 0x78, 0x2c, 0x22, 0x21, 0xd9, 0x2b, 0xda, 0x03, 0x30, 0x84, 0xf3,
      0xc5, 0x52, 0x64, 0x2b, 0x1d, 0xde, 0x50, 0xe0, 0xee, 0xca, 0xa2, 0x73, 0x7a, 0x93, 0x30, 0xa8, 0x47, 0x7f,
      0x6f, 0x41, 0xb0, 0xc8, 0x6e, 0x89, 0x1c, 0xcc, 0xf9, 0x01, 0x44, 0xc3, 0x08, 0xcf, 0x77, 0x47, 0xfc, 0xed,
      0x48, 0xf0, 0x4c, 0xe9, 0xc2, 0x3b, 0x7d, 0xef, 0x6e, 0xa4, 0x80, 0x40, 0x9e, 0x43, 0xb6, 0x77, 0x7a, 0x1d,
      0x51, 0xed, 0x98, 0x33, 0x93, 0xdd, 0x88, 0x01, 0x0e, 0xd3, 
    0x00, 
  0x00, 
  0xf2, 0xfa, 0x9d, 0x6e, 0x64, 0x6e, 0x00, 0xfa, 0x9d, 0x61, 0x62, 0x63, 0x00, 0x00,  // Name
  0x01, 0xa2, // SignedInfo
    0x03, 0xe2, // PublisherPublicKeyDigest
      0x02, 0x85, 0xb5, 0x50, 0x6b, 0x1a,
      0xba, 0x3d, 0xa7, 0x76, 0x1b, 0x0f, 0x8d, 0x61, 0xa4, 0xaa, 0x7e, 0x3b, 0x6d, 0x15, 0xb4, 0x26, 0xfe, 0xb5,
      0xbd, 0xa8, 0x23, 0x89, 0xac, 0xa7, 0x65, 0xa3, 0xb8, 0x1c, 
    0x00, 
    0x02, 0xba, // Timestamp
      0xb5, 0x05, 0x1d, 0xde, 0xe9, 0x5b, 0xdb, 
    0x00, 
    0x01, 0xe2, // KeyLocator
      0x01, 0xda, // Key
        0x0a, 0x95, 0x30, 0x81, 0x9f, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86,
        0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x81, 0x8d, 0x00, 0x30, 0x81, 0x89, 0x02, 0x81,
        0x81, 0x00, 0xe1, 0x7d, 0x30, 0xa7, 0xd8, 0x28, 0xab, 0x1b, 0x84, 0x0b, 0x17, 0x54, 0x2d, 0xca, 0xf6, 0x20,
        0x7a, 0xfd, 0x22, 0x1e, 0x08, 0x6b, 0x2a, 0x60, 0xd1, 0x6c, 0xb7, 0xf5, 0x44, 0x48, 0xba, 0x9f, 0x3f, 0x08,
        0xbc, 0xd0, 0x99, 0xdb, 0x21, 0xdd, 0x16, 0x2a, 0x77, 0x9e, 0x61, 0xaa, 0x89, 0xee, 0xe5, 0x54, 0xd3, 0xa4,
        0x7d, 0xe2, 0x30, 0xbc, 0x7a, 0xc5, 0x90, 0xd5, 0x24, 0x06, 0x7c, 0x38, 0x98, 0xbb, 0xa6, 0xf5, 0xdc, 0x43,
        0x60, 0xb8, 0x45, 0xed, 0xa4, 0x8c, 0xbd, 0x9c, 0xf1, 0x26, 0xa7, 0x23, 0x44, 0x5f, 0x0e, 0x19, 0x52, 0xd7,
        0x32, 0x5a, 0x75, 0xfa, 0xf5, 0x56, 0x14, 0x4f, 0x9a, 0x98, 0xaf, 0x71, 0x86, 0xb0, 0x27, 0x86, 0x85, 0xb8,
        0xe2, 0xc0, 0x8b, 0xea, 0x87, 0x17, 0x1b, 0x4d, 0xee, 0x58, 0x5c, 0x18, 0x28, 0x29, 0x5b, 0x53, 0x95, 0xeb,
        0x4a, 0x17, 0x77, 0x9f, 0x02, 0x03, 0x01, 0x00, 0x01, 
      0x00, 
    0x00, 
  0x00, 
  0x01, 0x9a, // Content
    0xc5, 0x53, 0x55, 0x43, 0x43, 0x45, 0x53, 0x53, 0x21, 
  0x00, 
0x00,
1
};

static void dumpData(const Data& data)
{
  cout << "name: " << data.getName().to_uri() << endl;
  if (data.getContent().size() > 0) {
    cout << "content (raw): ";
    for (unsigned int i = 0; i < data.getContent().size(); ++i)
      cout << (*data.getContent())[i];
    cout<< endl;
    cout << "content (hex): " << toHex(*data.getContent()) << endl;
  }
  else
    cout << "content: <empty>" << endl;
  
  cout << "metaInfo.timestamp: ";
  if (data.getMetaInfo().getTimestampMilliseconds() >= 0) {
    time_t seconds = data.getMetaInfo().getTimestampMilliseconds() / 1000.0;
    cout << data.getMetaInfo().getTimestampMilliseconds() << " milliseconds, UTC time: " << asctime(gmtime(&seconds));
  }
  else
    cout << "<none>" << endl;
  if (!(data.getMetaInfo().getType() < 0 || data.getMetaInfo().getType() == ndn_ContentType_DATA)) {
    cout << "metaInfo.type: ";
    if (data.getMetaInfo().getType() == ndn_ContentType_ENCR)
      cout << "ENCR" << endl;
    else if (data.getMetaInfo().getType() == ndn_ContentType_GONE)
      cout << "GONE" << endl;
    else if (data.getMetaInfo().getType() == ndn_ContentType_KEY)
      cout << "KEY" << endl;
    else if (data.getMetaInfo().getType() == ndn_ContentType_LINK)
      cout << "LINK" << endl;
    else if (data.getMetaInfo().getType() == ndn_ContentType_NACK)
      cout << "NACK" << endl;
  }
  cout << "metaInfo.freshnessSeconds: ";
  if (data.getMetaInfo().getFreshnessSeconds() >= 0)
    cout << data.getMetaInfo().getFreshnessSeconds() << endl;
  else
    cout << "<none>" << endl;
  cout << "metaInfo.finalBlockID: "
       << (data.getMetaInfo().getFinalBlockID().getValue().size() > 0 ? 
           toHex(*data.getMetaInfo().getFinalBlockID().getValue()).c_str() : "<none>") << endl;
    
  const Sha256WithRsaSignature *signature = dynamic_cast<const Sha256WithRsaSignature*>(data.getSignature());
  if (signature) {
    cout << "signature.digestAlgorithm: "
         << (signature->getDigestAlgorithm().size() > 0 ? toHex(*signature->getDigestAlgorithm()).c_str() : "default (sha-256)") << endl;
    cout << "signature.witness: "
         << (signature->getWitness().size() > 0 ? toHex(*signature->getWitness()).c_str() : "<none>") << endl;
    cout << "signature.signature: "
         << (signature->getSignature().size() > 0 ? toHex(*signature->getSignature()).c_str() : "<none>") << endl;
    cout << "signature.publisherPublicKeyDigest: "
         << (signature->getPublisherPublicKeyDigest().getPublisherPublicKeyDigest().size() > 0 ? 
           toHex(*signature->getPublisherPublicKeyDigest().getPublisherPublicKeyDigest()).c_str() : "<none>") << endl;
    cout << "signature.keyLocator: ";
    if ((int)signature->getKeyLocator().getType() >= 0) {
      if (signature->getKeyLocator().getType() == ndn_KeyLocatorType_KEY)
        cout << "Key: " << toHex(*signature->getKeyLocator().getKeyData()) << endl;
      else if (signature->getKeyLocator().getType() == ndn_KeyLocatorType_CERTIFICATE)
        cout << "Certificate: " << toHex(*signature->getKeyLocator().getKeyData()) << endl;
      else if (signature->getKeyLocator().getType() == ndn_KeyLocatorType_KEYNAME) {
        cout << "KeyName: " << signature->getKeyLocator().getKeyName().to_uri() << endl;
        cout << "signature.keyLocator: ";
        if ((int)signature->getKeyLocator().getKeyNameType() >= 0) {
          bool showKeyNameData = true;
          if (signature->getKeyLocator().getKeyNameType() == ndn_KeyNameType_PUBLISHER_PUBLIC_KEY_DIGEST)
            cout << "PublisherPublicKeyDigest: ";
          else if (signature->getKeyLocator().getKeyNameType() == ndn_KeyNameType_PUBLISHER_CERTIFICATE_DIGEST)
            cout << "PublisherCertificateDigest: ";
          else if (signature->getKeyLocator().getKeyNameType() == ndn_KeyNameType_PUBLISHER_ISSUER_KEY_DIGEST)
            cout << "PublisherIssuerKeyDigest: ";
          else if (signature->getKeyLocator().getKeyNameType() == ndn_KeyNameType_PUBLISHER_ISSUER_CERTIFICATE_DIGEST)
            cout << "PublisherIssuerCertificateDigest: ";
          else {
            cout << "<unrecognized ndn_KeyNameType " << signature->getKeyLocator().getKeyNameType() << ">" << endl;
            showKeyNameData = false;
          }
          if (showKeyNameData)
            cout << (signature->getKeyLocator().getKeyData().size() > 0 ?
                     toHex(*signature->getKeyLocator().getKeyData()).c_str() : "<none>") << endl;
        }
        else
          cout << "<no key digest>" << endl;
      }
      else
        cout << "<unrecognized ndn_KeyLocatorType " << signature->getKeyLocator().getType() << ">" << endl;
    }
    else
      cout << "<none>" << endl;
  }
}

static void onVerified(const char *prefix, const Data &data)
{
  cout << prefix << " signature verification: VERIFIED" << endl;
}

static void onVerifyFailed(const char *prefix)
{
  cout << prefix << " signature verification: FAILED" << endl;
}

int main(int argc, char** argv)
{
  try {
    Data data;
    data.wireDecode(Data1, sizeof(Data1));
    cout << "Decoded Data:" << endl;
    dumpData(data);
    
    Blob encoding = data.wireEncode();
    
    Data reDecodedData;
    reDecodedData.wireDecode(*encoding);
    cout << endl << "Re-decoded Data:" << endl;
    dumpData(reDecodedData);
  
    Data freshData(Name("/ndn/abc"));
    const unsigned char freshContent[] = "SUCCESS!";
    freshData.setContent(freshContent, sizeof(freshContent) - 1);
    freshData.getMetaInfo().setTimestampMilliseconds(time(NULL) * 1000.0);
    
    ptr_lib::shared_ptr<PrivateKeyStorage> privateKeyStorage(new PrivateKeyStorage());
    ptr_lib::shared_ptr<IdentityManager> identityManager(new IdentityManager(privateKeyStorage));
    KeyChain keyChain(identityManager);
    
    keyChain.signData(freshData);
    cout << endl << "Freshly-signed Data:" << endl;
    dumpData(freshData);
    Blob freshEncoding = freshData.wireEncode();

    // Do verification at the end because it uses callbacks.
    cout << endl;
    keyChain.verifyData(data, bind(&onVerified, "Decoded Data", _1), bind(&onVerifyFailed, "Decoded Data"));
    keyChain.verifyData(reDecodedData, bind(&onVerified, "Re-decoded Data", _1), bind(&onVerifyFailed, "Re-decoded Data"));
    keyChain.verifyData(freshData, bind(&onVerified, "Freshly-signed Data", _1), bind(&onVerifyFailed, "Freshly-signed Data"));
  } catch (std::exception& e) {
    cout << "exception: " << e.what() << endl;
  }
  return 0;
}
